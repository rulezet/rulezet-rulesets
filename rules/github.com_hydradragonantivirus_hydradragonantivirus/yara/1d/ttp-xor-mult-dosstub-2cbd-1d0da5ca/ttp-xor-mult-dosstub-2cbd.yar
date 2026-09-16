rule TTP_XOR_MULT_DOSStub_2cbd {
  strings:
    $key_2cbd = { 78 d5 [2] 0c cd [2] 4b cf [2] 0c de [2] 42 d2 [2] 4e d8 [2] 59 d3 [2] 42 9d [2] 7f }

  condition:
    any of them
}