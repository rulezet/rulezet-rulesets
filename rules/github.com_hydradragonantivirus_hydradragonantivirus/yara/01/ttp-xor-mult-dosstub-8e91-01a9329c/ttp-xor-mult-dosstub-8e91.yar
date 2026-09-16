rule TTP_XOR_MULT_DOSStub_8e91 {
  strings:
    $key_8e91 = { da f9 [2] ae e1 [2] e9 e3 [2] ae f2 [2] e0 fe [2] ec f4 [2] fb ff [2] e0 b1 [2] dd }

  condition:
    any of them
}