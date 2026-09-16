rule TTP_XOR_MULT_DOSStub_e28c {
  strings:
    $key_e28c = { b6 e4 [2] c2 fc [2] 85 fe [2] c2 ef [2] 8c e3 [2] 80 e9 [2] 97 e2 [2] 8c ac [2] b1 }

  condition:
    any of them
}