rule TTP_XOR_MULT_DOSStub_ebbf {
  strings:
    $key_ebbf = { bf d7 [2] cb cf [2] 8c cd [2] cb dc [2] 85 d0 [2] 89 da [2] 9e d1 [2] 85 9f [2] b8 }

  condition:
    any of them
}