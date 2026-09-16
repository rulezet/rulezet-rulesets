rule TTP_XOR_MULT_DOSStub_b58c {
  strings:
    $key_b58c = { e1 e4 [2] 95 fc [2] d2 fe [2] 95 ef [2] db e3 [2] d7 e9 [2] c0 e2 [2] db ac [2] e6 }

  condition:
    any of them
}