rule TTP_XOR_MULT_DOSStub_6a83 {
  strings:
    $key_6a83 = { 3e eb [2] 4a f3 [2] 0d f1 [2] 4a e0 [2] 04 ec [2] 08 e6 [2] 1f ed [2] 04 a3 [2] 39 }

  condition:
    any of them
}