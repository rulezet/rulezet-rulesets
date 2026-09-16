rule TTP_XOR_MULT_DOSStub_78ef {
  strings:
    $key_78ef = { 2c 87 [2] 58 9f [2] 1f 9d [2] 58 8c [2] 16 80 [2] 1a 8a [2] 0d 81 [2] 16 cf [2] 2b }

  condition:
    any of them
}