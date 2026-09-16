rule TTP_XOR_MULT_DOSStub_4cae {
  strings:
    $key_4cae = { 18 c6 [2] 6c de [2] 2b dc [2] 6c cd [2] 22 c1 [2] 2e cb [2] 39 c0 [2] 22 8e [2] 1f }

  condition:
    any of them
}