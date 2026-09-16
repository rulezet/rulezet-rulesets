rule TTP_XOR_MULT_DOSStub_438c {
  strings:
    $key_438c = { 17 e4 [2] 63 fc [2] 24 fe [2] 63 ef [2] 2d e3 [2] 21 e9 [2] 36 e2 [2] 2d ac [2] 10 }

  condition:
    any of them
}