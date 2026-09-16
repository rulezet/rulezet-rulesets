rule TTP_XOR_MULT_DOSStub_8e63 {
  strings:
    $key_8e63 = { da 0b [2] ae 13 [2] e9 11 [2] ae 00 [2] e0 0c [2] ec 06 [2] fb 0d [2] e0 43 [2] dd }

  condition:
    any of them
}