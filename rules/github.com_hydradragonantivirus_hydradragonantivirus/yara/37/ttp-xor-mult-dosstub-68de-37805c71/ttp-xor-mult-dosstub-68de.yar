rule TTP_XOR_MULT_DOSStub_68de {
  strings:
    $key_68de = { 3c b6 [2] 48 ae [2] 0f ac [2] 48 bd [2] 06 b1 [2] 0a bb [2] 1d b0 [2] 06 fe [2] 3b }

  condition:
    any of them
}