rule TTP_XOR_MULT_DOSStub_1f88 {
  strings:
    $key_1f88 = { 4b e0 [2] 3f f8 [2] 78 fa [2] 3f eb [2] 71 e7 [2] 7d ed [2] 6a e6 [2] 71 a8 [2] 4c }

  condition:
    any of them
}