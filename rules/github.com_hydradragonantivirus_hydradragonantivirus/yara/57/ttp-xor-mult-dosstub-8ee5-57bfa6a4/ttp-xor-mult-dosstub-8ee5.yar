rule TTP_XOR_MULT_DOSStub_8ee5 {
  strings:
    $key_8ee5 = { da 8d [2] ae 95 [2] e9 97 [2] ae 86 [2] e0 8a [2] ec 80 [2] fb 8b [2] e0 c5 [2] dd }

  condition:
    any of them
}