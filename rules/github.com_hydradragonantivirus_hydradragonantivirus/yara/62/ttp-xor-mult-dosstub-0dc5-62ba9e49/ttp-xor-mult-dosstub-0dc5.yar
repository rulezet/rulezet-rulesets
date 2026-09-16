rule TTP_XOR_MULT_DOSStub_0dc5 {
  strings:
    $key_0dc5 = { 59 ad [2] 2d b5 [2] 6a b7 [2] 2d a6 [2] 63 aa [2] 6f a0 [2] 78 ab [2] 63 e5 [2] 5e }

  condition:
    any of them
}