rule TTP_XOR_MULT_DOSStub_6e88 {
  strings:
    $key_6e88 = { 3a e0 [2] 4e f8 [2] 09 fa [2] 4e eb [2] 00 e7 [2] 0c ed [2] 1b e6 [2] 00 a8 [2] 3d }

  condition:
    any of them
}