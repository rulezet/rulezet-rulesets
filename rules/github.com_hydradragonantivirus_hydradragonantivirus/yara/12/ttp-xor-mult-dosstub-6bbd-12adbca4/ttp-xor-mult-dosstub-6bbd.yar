rule TTP_XOR_MULT_DOSStub_6bbd {
  strings:
    $key_6bbd = { 3f d5 [2] 4b cd [2] 0c cf [2] 4b de [2] 05 d2 [2] 09 d8 [2] 1e d3 [2] 05 9d [2] 38 }

  condition:
    any of them
}