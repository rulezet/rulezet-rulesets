rule TTP_XOR_MULT_DOSStub_25ef {
  strings:
    $key_25ef = { 71 87 [2] 05 9f [2] 42 9d [2] 05 8c [2] 4b 80 [2] 47 8a [2] 50 81 [2] 4b cf [2] 76 }

  condition:
    any of them
}