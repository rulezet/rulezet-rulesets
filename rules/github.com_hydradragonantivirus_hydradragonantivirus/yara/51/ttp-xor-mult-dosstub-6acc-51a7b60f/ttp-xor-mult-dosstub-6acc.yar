rule TTP_XOR_MULT_DOSStub_6acc {
  strings:
    $key_6acc = { 3e a4 [2] 4a bc [2] 0d be [2] 4a af [2] 04 a3 [2] 08 a9 [2] 1f a2 [2] 04 ec [2] 39 }

  condition:
    any of them
}