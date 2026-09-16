rule TTP_XOR_MULT_DOSStub_0cbd {
  strings:
    $key_0cbd = { 58 d5 [2] 2c cd [2] 6b cf [2] 2c de [2] 62 d2 [2] 6e d8 [2] 79 d3 [2] 62 9d [2] 5f }

  condition:
    any of them
}