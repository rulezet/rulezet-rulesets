rule TTP_XOR_MULT_DOSStub_8e49 {
  strings:
    $key_8e49 = { da 21 [2] ae 39 [2] e9 3b [2] ae 2a [2] e0 26 [2] ec 2c [2] fb 27 [2] e0 69 [2] dd }

  condition:
    any of them
}