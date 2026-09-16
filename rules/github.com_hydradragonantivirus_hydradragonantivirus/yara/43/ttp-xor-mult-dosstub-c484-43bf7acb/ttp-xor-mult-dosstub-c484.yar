rule TTP_XOR_MULT_DOSStub_c484 {
  strings:
    $key_c484 = { 90 ec [2] e4 f4 [2] a3 f6 [2] e4 e7 [2] aa eb [2] a6 e1 [2] b1 ea [2] aa a4 [2] 97 }

  condition:
    any of them
}