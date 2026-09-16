rule TTP_XOR_MULT_DOSStub_058a {
  strings:
    $key_058a = { 51 e2 [2] 25 fa [2] 62 f8 [2] 25 e9 [2] 6b e5 [2] 67 ef [2] 70 e4 [2] 6b aa [2] 56 }

  condition:
    any of them
}