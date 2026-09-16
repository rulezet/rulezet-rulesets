rule TTP_XOR_MULT_DOSStub_07ef {
  strings:
    $key_07ef = { 53 87 [2] 27 9f [2] 60 9d [2] 27 8c [2] 69 80 [2] 65 8a [2] 72 81 [2] 69 cf [2] 54 }

  condition:
    any of them
}