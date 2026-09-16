rule TTP_XOR_MULT_DOSStub_66ef {
  strings:
    $key_66ef = { 32 87 [2] 46 9f [2] 01 9d [2] 46 8c [2] 08 80 [2] 04 8a [2] 13 81 [2] 08 cf [2] 35 }

  condition:
    any of them
}