rule TTP_XOR_MULT_DOSStub_05bd {
  strings:
    $key_05bd = { 51 d5 [2] 25 cd [2] 62 cf [2] 25 de [2] 6b d2 [2] 67 d8 [2] 70 d3 [2] 6b 9d [2] 56 }

  condition:
    any of them
}