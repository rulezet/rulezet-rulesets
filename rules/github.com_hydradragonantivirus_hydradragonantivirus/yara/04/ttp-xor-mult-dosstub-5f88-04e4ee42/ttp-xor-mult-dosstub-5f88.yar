rule TTP_XOR_MULT_DOSStub_5f88 {
  strings:
    $key_5f88 = { 0b e0 [2] 7f f8 [2] 38 fa [2] 7f eb [2] 31 e7 [2] 3d ed [2] 2a e6 [2] 31 a8 [2] 0c }

  condition:
    any of them
}