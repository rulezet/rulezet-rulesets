rule TTP_XOR_MULT_DOSStub_128c {
  strings:
    $key_128c = { 46 e4 [2] 32 fc [2] 75 fe [2] 32 ef [2] 7c e3 [2] 70 e9 [2] 67 e2 [2] 7c ac [2] 41 }

  condition:
    any of them
}