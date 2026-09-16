rule TTP_XOR_MULT_DOSStub_29de {
  strings:
    $key_29de = { 7d b6 [2] 09 ae [2] 4e ac [2] 09 bd [2] 47 b1 [2] 4b bb [2] 5c b0 [2] 47 fe [2] 7a }

  condition:
    any of them
}