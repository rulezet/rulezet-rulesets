rule TTP_XOR_MULT_DOSStub_f38c {
  strings:
    $key_f38c = { a7 e4 [2] d3 fc [2] 94 fe [2] d3 ef [2] 9d e3 [2] 91 e9 [2] 86 e2 [2] 9d ac [2] a0 }

  condition:
    any of them
}