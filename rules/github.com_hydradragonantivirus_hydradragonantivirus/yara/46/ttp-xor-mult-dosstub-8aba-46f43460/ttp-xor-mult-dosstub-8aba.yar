rule TTP_XOR_MULT_DOSStub_8aba {
  strings:
    $key_8aba = { de d2 [2] aa ca [2] ed c8 [2] aa d9 [2] e4 d5 [2] e8 df [2] ff d4 [2] e4 9a [2] d9 }

  condition:
    any of them
}