rule TTP_XOR_MULT_DOSStub_16bf {
  strings:
    $key_16bf = { 42 d7 [2] 36 cf [2] 71 cd [2] 36 dc [2] 78 d0 [2] 74 da [2] 63 d1 [2] 78 9f [2] 45 }

  condition:
    any of them
}