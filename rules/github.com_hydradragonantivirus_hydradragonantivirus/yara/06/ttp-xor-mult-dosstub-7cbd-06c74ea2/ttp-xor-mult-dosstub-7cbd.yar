rule TTP_XOR_MULT_DOSStub_7cbd {
  strings:
    $key_7cbd = { 28 d5 [2] 5c cd [2] 1b cf [2] 5c de [2] 12 d2 [2] 1e d8 [2] 09 d3 [2] 12 9d [2] 2f }

  condition:
    any of them
}