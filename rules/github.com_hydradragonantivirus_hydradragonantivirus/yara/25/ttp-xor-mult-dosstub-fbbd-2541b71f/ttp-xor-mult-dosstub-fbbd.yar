rule TTP_XOR_MULT_DOSStub_fbbd {
  strings:
    $key_fbbd = { af d5 [2] db cd [2] 9c cf [2] db de [2] 95 d2 [2] 99 d8 [2] 8e d3 [2] 95 9d [2] a8 }

  condition:
    any of them
}