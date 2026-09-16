rule TTP_XOR_MULT_DOSStub_f58c {
  strings:
    $key_f58c = { a1 e4 [2] d5 fc [2] 92 fe [2] d5 ef [2] 9b e3 [2] 97 e9 [2] 80 e2 [2] 9b ac [2] a6 }

  condition:
    any of them
}