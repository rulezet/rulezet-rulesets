rule TTP_XOR_MULT_DOSStub_2f88 {
  strings:
    $key_2f88 = { 7b e0 [2] 0f f8 [2] 48 fa [2] 0f eb [2] 41 e7 [2] 4d ed [2] 5a e6 [2] 41 a8 [2] 7c }

  condition:
    any of them
}