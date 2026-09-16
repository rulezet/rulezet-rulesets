rule TTP_XOR_MULT_DOSStub_1cae {
  strings:
    $key_1cae = { 48 c6 [2] 3c de [2] 7b dc [2] 3c cd [2] 72 c1 [2] 7e cb [2] 69 c0 [2] 72 8e [2] 4f }

  condition:
    any of them
}