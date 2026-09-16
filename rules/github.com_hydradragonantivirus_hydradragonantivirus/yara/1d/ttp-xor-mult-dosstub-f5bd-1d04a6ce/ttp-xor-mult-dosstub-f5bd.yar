rule TTP_XOR_MULT_DOSStub_f5bd {
  strings:
    $key_f5bd = { a1 d5 [2] d5 cd [2] 92 cf [2] d5 de [2] 9b d2 [2] 97 d8 [2] 80 d3 [2] 9b 9d [2] a6 }

  condition:
    any of them
}