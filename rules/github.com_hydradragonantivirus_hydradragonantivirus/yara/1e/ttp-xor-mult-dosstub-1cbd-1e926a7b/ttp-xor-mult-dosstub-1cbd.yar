rule TTP_XOR_MULT_DOSStub_1cbd {
  strings:
    $key_1cbd = { 48 d5 [2] 3c cd [2] 7b cf [2] 3c de [2] 72 d2 [2] 7e d8 [2] 69 d3 [2] 72 9d [2] 4f }

  condition:
    any of them
}