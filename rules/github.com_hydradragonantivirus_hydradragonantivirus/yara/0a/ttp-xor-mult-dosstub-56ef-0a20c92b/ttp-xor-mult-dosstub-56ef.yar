rule TTP_XOR_MULT_DOSStub_56ef {
  strings:
    $key_56ef = { 02 87 [2] 76 9f [2] 31 9d [2] 76 8c [2] 38 80 [2] 34 8a [2] 23 81 [2] 38 cf [2] 05 }

  condition:
    any of them
}