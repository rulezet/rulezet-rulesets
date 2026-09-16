rule TTP_XOR_MULT_DOSStub_f9de {
  strings:
    $key_f9de = { ad b6 [2] d9 ae [2] 9e ac [2] d9 bd [2] 97 b1 [2] 9b bb [2] 8c b0 [2] 97 fe [2] aa }

  condition:
    any of them
}