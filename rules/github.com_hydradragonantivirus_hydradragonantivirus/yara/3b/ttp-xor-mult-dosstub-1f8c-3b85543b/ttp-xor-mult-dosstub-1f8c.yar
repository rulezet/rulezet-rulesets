rule TTP_XOR_MULT_DOSStub_1f8c {
  strings:
    $key_1f8c = { 4b e4 [2] 3f fc [2] 78 fe [2] 3f ef [2] 71 e3 [2] 7d e9 [2] 6a e2 [2] 71 ac [2] 4c }

  condition:
    any of them
}