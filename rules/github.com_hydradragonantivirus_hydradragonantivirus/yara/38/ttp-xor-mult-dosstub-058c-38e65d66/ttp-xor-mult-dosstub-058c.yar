rule TTP_XOR_MULT_DOSStub_058c {
  strings:
    $key_058c = { 51 e4 [2] 25 fc [2] 62 fe [2] 25 ef [2] 6b e3 [2] 67 e9 [2] 70 e2 [2] 6b ac [2] 56 }

  condition:
    any of them
}