rule TTP_XOR_MULT_DOSStub_b08c {
  strings:
    $key_b08c = { e4 e4 [2] 90 fc [2] d7 fe [2] 90 ef [2] de e3 [2] d2 e9 [2] c5 e2 [2] de ac [2] e3 }

  condition:
    any of them
}