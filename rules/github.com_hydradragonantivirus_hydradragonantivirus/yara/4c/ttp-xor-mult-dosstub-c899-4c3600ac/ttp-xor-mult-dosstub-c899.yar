rule TTP_XOR_MULT_DOSStub_c899 {
  strings:
    $key_c899 = { 9c f1 [2] e8 e9 [2] af eb [2] e8 fa [2] a6 f6 [2] aa fc [2] bd f7 [2] a6 b9 [2] 9b }

  condition:
    any of them
}