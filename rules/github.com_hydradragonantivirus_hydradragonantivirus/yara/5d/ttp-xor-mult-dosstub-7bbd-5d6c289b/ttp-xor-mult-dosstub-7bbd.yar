rule TTP_XOR_MULT_DOSStub_7bbd {
  strings:
    $key_7bbd = { 2f d5 [2] 5b cd [2] 1c cf [2] 5b de [2] 15 d2 [2] 19 d8 [2] 0e d3 [2] 15 9d [2] 28 }

  condition:
    any of them
}