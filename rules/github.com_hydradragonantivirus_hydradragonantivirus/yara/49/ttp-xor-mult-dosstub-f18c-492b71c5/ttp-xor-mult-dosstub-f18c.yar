rule TTP_XOR_MULT_DOSStub_f18c {
  strings:
    $key_f18c = { a5 e4 [2] d1 fc [2] 96 fe [2] d1 ef [2] 9f e3 [2] 93 e9 [2] 84 e2 [2] 9f ac [2] a2 }

  condition:
    any of them
}