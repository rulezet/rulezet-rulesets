rule TTP_XOR_MULT_DOSStub_e2aa {
  strings:
    $key_e2aa = { b6 c2 [2] c2 da [2] 85 d8 [2] c2 c9 [2] 8c c5 [2] 80 cf [2] 97 c4 [2] 8c 8a [2] b1 }

  condition:
    any of them
}