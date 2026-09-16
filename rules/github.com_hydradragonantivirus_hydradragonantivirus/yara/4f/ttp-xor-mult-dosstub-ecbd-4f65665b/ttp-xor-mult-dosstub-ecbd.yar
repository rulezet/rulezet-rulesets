rule TTP_XOR_MULT_DOSStub_ecbd {
  strings:
    $key_ecbd = { b8 d5 [2] cc cd [2] 8b cf [2] cc de [2] 82 d2 [2] 8e d8 [2] 99 d3 [2] 82 9d [2] bf }

  condition:
    any of them
}