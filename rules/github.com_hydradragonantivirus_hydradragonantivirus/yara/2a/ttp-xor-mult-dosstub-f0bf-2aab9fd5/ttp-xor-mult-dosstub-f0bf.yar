rule TTP_XOR_MULT_DOSStub_f0bf {
  strings:
    $key_f0bf = { a4 d7 [2] d0 cf [2] 97 cd [2] d0 dc [2] 9e d0 [2] 92 da [2] 85 d1 [2] 9e 9f [2] a3 }

  condition:
    any of them
}