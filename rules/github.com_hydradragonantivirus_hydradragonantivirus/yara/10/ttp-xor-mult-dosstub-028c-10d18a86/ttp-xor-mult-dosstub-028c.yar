rule TTP_XOR_MULT_DOSStub_028c {
  strings:
    $key_028c = { 56 e4 [2] 22 fc [2] 65 fe [2] 22 ef [2] 6c e3 [2] 60 e9 [2] 77 e2 [2] 6c ac [2] 51 }

  condition:
    any of them
}