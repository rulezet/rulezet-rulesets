rule TTP_XOR_MULT_DOSStub_2996 {
  strings:
    $key_2996 = { 7d fe [2] 09 e6 [2] 4e e4 [2] 09 f5 [2] 47 f9 [2] 4b f3 [2] 5c f8 [2] 47 b6 [2] 7a }

  condition:
    any of them
}