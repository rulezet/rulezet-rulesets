rule TTP_XOR_MULT_DOSStub_0cfe {
  strings:
    $key_0cfe = { 58 96 [2] 2c 8e [2] 6b 8c [2] 2c 9d [2] 62 91 [2] 6e 9b [2] 79 90 [2] 62 de [2] 5f }

  condition:
    any of them
}