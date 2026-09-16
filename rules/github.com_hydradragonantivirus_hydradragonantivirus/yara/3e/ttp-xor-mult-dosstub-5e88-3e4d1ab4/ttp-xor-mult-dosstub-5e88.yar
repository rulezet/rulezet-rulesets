rule TTP_XOR_MULT_DOSStub_5e88 {
  strings:
    $key_5e88 = { 0a e0 [2] 7e f8 [2] 39 fa [2] 7e eb [2] 30 e7 [2] 3c ed [2] 2b e6 [2] 30 a8 [2] 0d }

  condition:
    any of them
}