rule TTP_XOR_MULT_DOSStub_32ef {
  strings:
    $key_32ef = { 66 87 [2] 12 9f [2] 55 9d [2] 12 8c [2] 5c 80 [2] 50 8a [2] 47 81 [2] 5c cf [2] 61 }

  condition:
    any of them
}