rule TTP_XOR_MULT_DOSStub_7acc {
  strings:
    $key_7acc = { 2e a4 [2] 5a bc [2] 1d be [2] 5a af [2] 14 a3 [2] 18 a9 [2] 0f a2 [2] 14 ec [2] 29 }

  condition:
    any of them
}