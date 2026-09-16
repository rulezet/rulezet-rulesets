rule TTP_XOR_MULT_DOSStub_c3bf {
  strings:
    $key_c3bf = { 97 d7 [2] e3 cf [2] a4 cd [2] e3 dc [2] ad d0 [2] a1 da [2] b6 d1 [2] ad 9f [2] 90 }

  condition:
    any of them
}