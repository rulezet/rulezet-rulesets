rule TTP_XOR_MULT_DOSStub_2acc {
  strings:
    $key_2acc = { 7e a4 [2] 0a bc [2] 4d be [2] 0a af [2] 44 a3 [2] 48 a9 [2] 5f a2 [2] 44 ec [2] 79 }

  condition:
    any of them
}