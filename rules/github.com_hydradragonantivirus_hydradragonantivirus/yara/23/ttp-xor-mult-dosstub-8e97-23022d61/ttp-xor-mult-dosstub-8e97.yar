rule TTP_XOR_MULT_DOSStub_8e97 {
  strings:
    $key_8e97 = { da ff [2] ae e7 [2] e9 e5 [2] ae f4 [2] e0 f8 [2] ec f2 [2] fb f9 [2] e0 b7 [2] dd }

  condition:
    any of them
}