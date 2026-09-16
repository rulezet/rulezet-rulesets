rule TTP_XOR_MULT_DOSStub_0acc {
  strings:
    $key_0acc = { 5e a4 [2] 2a bc [2] 6d be [2] 2a af [2] 64 a3 [2] 68 a9 [2] 7f a2 [2] 64 ec [2] 59 }

  condition:
    any of them
}