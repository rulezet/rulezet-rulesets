rule TTP_XOR_MULT_DOSStub_16ef {
  strings:
    $key_16ef = { 42 87 [2] 36 9f [2] 71 9d [2] 36 8c [2] 78 80 [2] 74 8a [2] 63 81 [2] 78 cf [2] 45 }

  condition:
    any of them
}