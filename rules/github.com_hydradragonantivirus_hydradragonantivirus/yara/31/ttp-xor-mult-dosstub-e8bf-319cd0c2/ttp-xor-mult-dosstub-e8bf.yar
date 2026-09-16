rule TTP_XOR_MULT_DOSStub_e8bf {
  strings:
    $key_e8bf = { bc d7 [2] c8 cf [2] 8f cd [2] c8 dc [2] 86 d0 [2] 8a da [2] 9d d1 [2] 86 9f [2] bb }

  condition:
    any of them
}