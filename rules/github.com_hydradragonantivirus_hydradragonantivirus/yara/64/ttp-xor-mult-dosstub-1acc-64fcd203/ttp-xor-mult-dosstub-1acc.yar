rule TTP_XOR_MULT_DOSStub_1acc {
  strings:
    $key_1acc = { 4e a4 [2] 3a bc [2] 7d be [2] 3a af [2] 74 a3 [2] 78 a9 [2] 6f a2 [2] 74 ec [2] 49 }

  condition:
    any of them
}