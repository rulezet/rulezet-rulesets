rule TTP_XOR_MULT_DOSStub_238c {
  strings:
    $key_238c = { 77 e4 [2] 03 fc [2] 44 fe [2] 03 ef [2] 4d e3 [2] 41 e9 [2] 56 e2 [2] 4d ac [2] 70 }

  condition:
    any of them
}