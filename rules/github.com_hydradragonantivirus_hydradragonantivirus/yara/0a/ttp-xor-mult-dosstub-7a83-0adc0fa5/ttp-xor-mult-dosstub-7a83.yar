rule TTP_XOR_MULT_DOSStub_7a83 {
  strings:
    $key_7a83 = { 2e eb [2] 5a f3 [2] 1d f1 [2] 5a e0 [2] 14 ec [2] 18 e6 [2] 0f ed [2] 14 a3 [2] 29 }

  condition:
    any of them
}