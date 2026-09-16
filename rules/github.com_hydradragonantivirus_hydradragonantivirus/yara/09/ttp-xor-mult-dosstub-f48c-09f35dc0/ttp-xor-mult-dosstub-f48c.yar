rule TTP_XOR_MULT_DOSStub_f48c {
  strings:
    $key_f48c = { a0 e4 [2] d4 fc [2] 93 fe [2] d4 ef [2] 9a e3 [2] 96 e9 [2] 81 e2 [2] 9a ac [2] a7 }

  condition:
    any of them
}