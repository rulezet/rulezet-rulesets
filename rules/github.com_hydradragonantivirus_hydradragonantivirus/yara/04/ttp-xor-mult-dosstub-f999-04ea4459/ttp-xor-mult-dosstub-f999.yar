rule TTP_XOR_MULT_DOSStub_f999 {
  strings:
    $key_f999 = { ad f1 [2] d9 e9 [2] 9e eb [2] d9 fa [2] 97 f6 [2] 9b fc [2] 8c f7 [2] 97 b9 [2] aa }

  condition:
    any of them
}