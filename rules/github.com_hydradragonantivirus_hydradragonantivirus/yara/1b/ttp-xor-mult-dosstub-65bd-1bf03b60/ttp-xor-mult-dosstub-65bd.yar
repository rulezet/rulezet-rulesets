rule TTP_XOR_MULT_DOSStub_65bd {
  strings:
    $key_65bd = { 31 d5 [2] 45 cd [2] 02 cf [2] 45 de [2] 0b d2 [2] 07 d8 [2] 10 d3 [2] 0b 9d [2] 36 }

  condition:
    any of them
}