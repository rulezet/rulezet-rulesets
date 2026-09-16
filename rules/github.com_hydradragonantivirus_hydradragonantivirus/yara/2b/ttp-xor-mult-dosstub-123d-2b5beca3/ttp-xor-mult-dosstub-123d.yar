rule TTP_XOR_MULT_DOSStub_123d {
  strings:
    $key_123d = { 46 55 [2] 32 4d [2] 75 4f [2] 32 5e [2] 7c 52 [2] 70 58 [2] 67 53 [2] 7c 1d [2] 41 }

  condition:
    any of them
}