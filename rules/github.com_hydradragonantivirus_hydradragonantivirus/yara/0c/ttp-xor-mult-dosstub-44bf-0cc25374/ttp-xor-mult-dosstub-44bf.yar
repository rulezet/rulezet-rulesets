rule TTP_XOR_MULT_DOSStub_44bf {
  strings:
    $key_44bf = { 10 d7 [2] 64 cf [2] 23 cd [2] 64 dc [2] 2a d0 [2] 26 da [2] 31 d1 [2] 2a 9f [2] 17 }

  condition:
    any of them
}