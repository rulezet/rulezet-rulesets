rule TTP_XOR_MULT_DOSStub_45bf {
  strings:
    $key_45bf = { 11 d7 [2] 65 cf [2] 22 cd [2] 65 dc [2] 2b d0 [2] 27 da [2] 30 d1 [2] 2b 9f [2] 16 }

  condition:
    any of them
}