rule TTP_XOR_MULT_DOSStub_1f8a {
  strings:
    $key_1f8a = { 4b e2 [2] 3f fa [2] 78 f8 [2] 3f e9 [2] 71 e5 [2] 7d ef [2] 6a e4 [2] 71 aa [2] 4c }

  condition:
    any of them
}