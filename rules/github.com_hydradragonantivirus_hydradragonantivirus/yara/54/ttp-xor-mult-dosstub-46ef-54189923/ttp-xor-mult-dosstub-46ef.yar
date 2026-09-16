rule TTP_XOR_MULT_DOSStub_46ef {
  strings:
    $key_46ef = { 12 87 [2] 66 9f [2] 21 9d [2] 66 8c [2] 28 80 [2] 24 8a [2] 33 81 [2] 28 cf [2] 15 }

  condition:
    any of them
}