rule TTP_XOR_MULT_DOSStub_6dc5 {
  strings:
    $key_6dc5 = { 39 ad [2] 4d b5 [2] 0a b7 [2] 4d a6 [2] 03 aa [2] 0f a0 [2] 18 ab [2] 03 e5 [2] 3e }

  condition:
    any of them
}