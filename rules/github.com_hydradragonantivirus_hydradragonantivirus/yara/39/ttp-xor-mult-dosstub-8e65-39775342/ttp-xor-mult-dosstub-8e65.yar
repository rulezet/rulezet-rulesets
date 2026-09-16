rule TTP_XOR_MULT_DOSStub_8e65 {
  strings:
    $key_8e65 = { da 0d [2] ae 15 [2] e9 17 [2] ae 06 [2] e0 0a [2] ec 00 [2] fb 0b [2] e0 45 [2] dd }

  condition:
    any of them
}