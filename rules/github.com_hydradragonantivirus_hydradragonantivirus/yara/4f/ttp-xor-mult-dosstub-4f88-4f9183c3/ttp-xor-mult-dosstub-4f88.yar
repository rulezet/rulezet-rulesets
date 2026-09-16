rule TTP_XOR_MULT_DOSStub_4f88 {
  strings:
    $key_4f88 = { 1b e0 [2] 6f f8 [2] 28 fa [2] 6f eb [2] 21 e7 [2] 2d ed [2] 3a e6 [2] 21 a8 [2] 1c }

  condition:
    any of them
}