rule TTP_XOR_MULT_DOSStub_6dc0 {
  strings:
    $key_6dc0 = { 39 a8 [2] 4d b0 [2] 0a b2 [2] 4d a3 [2] 03 af [2] 0f a5 [2] 18 ae [2] 03 e0 [2] 3e }

  condition:
    any of them
}