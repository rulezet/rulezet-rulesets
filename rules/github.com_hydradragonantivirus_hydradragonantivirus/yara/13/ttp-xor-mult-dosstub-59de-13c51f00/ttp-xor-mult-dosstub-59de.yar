rule TTP_XOR_MULT_DOSStub_59de {
  strings:
    $key_59de = { 0d b6 [2] 79 ae [2] 3e ac [2] 79 bd [2] 37 b1 [2] 3b bb [2] 2c b0 [2] 37 fe [2] 0a }

  condition:
    any of them
}