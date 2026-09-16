rule TTP_XOR_MULT_DOSStub_62ef {
  strings:
    $key_62ef = { 36 87 [2] 42 9f [2] 05 9d [2] 42 8c [2] 0c 80 [2] 00 8a [2] 17 81 [2] 0c cf [2] 31 }

  condition:
    any of them
}