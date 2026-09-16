rule TTP_XOR_MULT_DOSStub_8e9a {
  strings:
    $key_8e9a = { da f2 [2] ae ea [2] e9 e8 [2] ae f9 [2] e0 f5 [2] ec ff [2] fb f4 [2] e0 ba [2] dd }

  condition:
    any of them
}