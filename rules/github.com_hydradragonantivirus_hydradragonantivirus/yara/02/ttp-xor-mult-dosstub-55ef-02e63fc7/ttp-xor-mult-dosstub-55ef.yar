rule TTP_XOR_MULT_DOSStub_55ef {
  strings:
    $key_55ef = { 01 87 [2] 75 9f [2] 32 9d [2] 75 8c [2] 3b 80 [2] 37 8a [2] 20 81 [2] 3b cf [2] 06 }

  condition:
    any of them
}