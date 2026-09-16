rule TTP_XOR_MULT_DOSStub_27bf {
  strings:
    $key_27bf = { 73 d7 [2] 07 cf [2] 40 cd [2] 07 dc [2] 49 d0 [2] 45 da [2] 52 d1 [2] 49 9f [2] 74 }

  condition:
    any of them
}