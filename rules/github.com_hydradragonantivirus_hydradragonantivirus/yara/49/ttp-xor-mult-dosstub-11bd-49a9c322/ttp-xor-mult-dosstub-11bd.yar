rule TTP_XOR_MULT_DOSStub_11bd {
  strings:
    $key_11bd = { 45 d5 [2] 31 cd [2] 76 cf [2] 31 de [2] 7f d2 [2] 73 d8 [2] 64 d3 [2] 7f 9d [2] 42 }

  condition:
    any of them
}