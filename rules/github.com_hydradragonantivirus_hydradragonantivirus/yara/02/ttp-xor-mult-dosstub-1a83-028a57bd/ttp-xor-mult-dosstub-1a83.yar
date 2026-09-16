rule TTP_XOR_MULT_DOSStub_1a83 {
  strings:
    $key_1a83 = { 4e eb [2] 3a f3 [2] 7d f1 [2] 3a e0 [2] 74 ec [2] 78 e6 [2] 6f ed [2] 74 a3 [2] 49 }

  condition:
    any of them
}