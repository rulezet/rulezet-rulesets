rule TTP_XOR_MULT_DOSStub_5ec6 {
  strings:
    $key_5ec6 = { 0a ae [2] 7e b6 [2] 39 b4 [2] 7e a5 [2] 30 a9 [2] 3c a3 [2] 2b a8 [2] 30 e6 [2] 0d }

  condition:
    any of them
}