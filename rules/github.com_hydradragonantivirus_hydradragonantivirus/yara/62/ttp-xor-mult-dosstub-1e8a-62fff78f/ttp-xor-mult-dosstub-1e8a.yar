rule TTP_XOR_MULT_DOSStub_1e8a {
  strings:
    $key_1e8a = { 4a e2 [2] 3e fa [2] 79 f8 [2] 3e e9 [2] 70 e5 [2] 7c ef [2] 6b e4 [2] 70 aa [2] 4d }

  condition:
    any of them
}