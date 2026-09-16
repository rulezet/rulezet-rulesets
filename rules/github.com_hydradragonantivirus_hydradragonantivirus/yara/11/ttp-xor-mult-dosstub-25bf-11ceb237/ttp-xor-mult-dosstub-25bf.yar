rule TTP_XOR_MULT_DOSStub_25bf {
  strings:
    $key_25bf = { 71 d7 [2] 05 cf [2] 42 cd [2] 05 dc [2] 4b d0 [2] 47 da [2] 50 d1 [2] 4b 9f [2] 76 }

  condition:
    any of them
}