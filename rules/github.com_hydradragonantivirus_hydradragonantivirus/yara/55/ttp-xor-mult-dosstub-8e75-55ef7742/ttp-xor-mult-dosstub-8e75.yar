rule TTP_XOR_MULT_DOSStub_8e75 {
  strings:
    $key_8e75 = { da 1d [2] ae 05 [2] e9 07 [2] ae 16 [2] e0 1a [2] ec 10 [2] fb 1b [2] e0 55 [2] dd }

  condition:
    any of them
}