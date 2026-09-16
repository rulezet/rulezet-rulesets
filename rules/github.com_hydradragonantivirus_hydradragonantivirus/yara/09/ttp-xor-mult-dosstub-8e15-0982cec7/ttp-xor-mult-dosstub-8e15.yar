rule TTP_XOR_MULT_DOSStub_8e15 {
  strings:
    $key_8e15 = { da 7d [2] ae 65 [2] e9 67 [2] ae 76 [2] e0 7a [2] ec 70 [2] fb 7b [2] e0 35 [2] dd }

  condition:
    any of them
}