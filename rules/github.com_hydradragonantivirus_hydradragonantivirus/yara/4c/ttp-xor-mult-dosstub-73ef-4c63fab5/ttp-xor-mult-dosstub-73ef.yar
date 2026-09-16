rule TTP_XOR_MULT_DOSStub_73ef {
  strings:
    $key_73ef = { 27 87 [2] 53 9f [2] 14 9d [2] 53 8c [2] 1d 80 [2] 11 8a [2] 06 81 [2] 1d cf [2] 20 }

  condition:
    any of them
}