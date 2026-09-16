rule TTP_XOR_MULT_DOSStub_228c {
  strings:
    $key_228c = { 76 e4 [2] 02 fc [2] 45 fe [2] 02 ef [2] 4c e3 [2] 40 e9 [2] 57 e2 [2] 4c ac [2] 71 }

  condition:
    any of them
}