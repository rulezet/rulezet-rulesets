rule TTP_XOR_MULT_DOSStub_54ef {
  strings:
    $key_54ef = { 00 87 [2] 74 9f [2] 33 9d [2] 74 8c [2] 3a 80 [2] 36 8a [2] 21 81 [2] 3a cf [2] 07 }

  condition:
    any of them
}