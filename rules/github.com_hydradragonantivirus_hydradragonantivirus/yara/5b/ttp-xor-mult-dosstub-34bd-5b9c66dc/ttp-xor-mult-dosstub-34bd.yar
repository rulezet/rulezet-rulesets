rule TTP_XOR_MULT_DOSStub_34bd {
  strings:
    $key_34bd = { 60 d5 [2] 14 cd [2] 53 cf [2] 14 de [2] 5a d2 [2] 56 d8 [2] 41 d3 [2] 5a 9d [2] 67 }

  condition:
    any of them
}