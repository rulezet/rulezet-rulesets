rule TTP_XOR_MULT_DOSStub_35ef {
  strings:
    $key_35ef = { 61 87 [2] 15 9f [2] 52 9d [2] 15 8c [2] 5b 80 [2] 57 8a [2] 40 81 [2] 5b cf [2] 66 }

  condition:
    any of them
}