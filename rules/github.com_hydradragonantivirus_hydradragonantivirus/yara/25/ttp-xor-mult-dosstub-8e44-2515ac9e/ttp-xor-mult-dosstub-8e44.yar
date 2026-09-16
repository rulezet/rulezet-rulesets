rule TTP_XOR_MULT_DOSStub_8e44 {
  strings:
    $key_8e44 = { da 2c [2] ae 34 [2] e9 36 [2] ae 27 [2] e0 2b [2] ec 21 [2] fb 2a [2] e0 64 [2] dd }

  condition:
    any of them
}