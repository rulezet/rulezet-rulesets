rule TTP_XOR_MULT_DOSStub_2cae {
  strings:
    $key_2cae = { 78 c6 [2] 0c de [2] 4b dc [2] 0c cd [2] 42 c1 [2] 4e cb [2] 59 c0 [2] 42 8e [2] 7f }

  condition:
    any of them
}