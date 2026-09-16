rule TTP_XOR_MULT_DOSStub_8ee4 {
  strings:
    $key_8ee4 = { da 8c [2] ae 94 [2] e9 96 [2] ae 87 [2] e0 8b [2] ec 81 [2] fb 8a [2] e0 c4 [2] dd }

  condition:
    any of them
}