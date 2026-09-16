rule TTP_XOR_MULT_DOSStub_3e88 {
  strings:
    $key_3e88 = { 6a e0 [2] 1e f8 [2] 59 fa [2] 1e eb [2] 50 e7 [2] 5c ed [2] 4b e6 [2] 50 a8 [2] 6d }

  condition:
    any of them
}