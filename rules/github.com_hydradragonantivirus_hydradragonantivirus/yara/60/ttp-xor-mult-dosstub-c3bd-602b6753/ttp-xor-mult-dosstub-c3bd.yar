rule TTP_XOR_MULT_DOSStub_c3bd {
  strings:
    $key_c3bd = { 97 d5 [2] e3 cd [2] a4 cf [2] e3 de [2] ad d2 [2] a1 d8 [2] b6 d3 [2] ad 9d [2] 90 }

  condition:
    any of them
}