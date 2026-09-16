rule TTP_XOR_MULT_DOSStub_8e78 {
  strings:
    $key_8e78 = { da 10 [2] ae 08 [2] e9 0a [2] ae 1b [2] e0 17 [2] ec 1d [2] fb 16 [2] e0 58 [2] dd }

  condition:
    any of them
}