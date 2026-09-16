rule TTP_XOR_MULT_DOSStub_67bf {
  strings:
    $key_67bf = { 33 d7 [2] 47 cf [2] 00 cd [2] 47 dc [2] 09 d0 [2] 05 da [2] 12 d1 [2] 09 9f [2] 34 }

  condition:
    any of them
}