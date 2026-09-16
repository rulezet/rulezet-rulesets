rule TTP_XOR_MULT_DOSStub_70ef {
  strings:
    $key_70ef = { 24 87 [2] 50 9f [2] 17 9d [2] 50 8c [2] 1e 80 [2] 12 8a [2] 05 81 [2] 1e cf [2] 23 }

  condition:
    any of them
}