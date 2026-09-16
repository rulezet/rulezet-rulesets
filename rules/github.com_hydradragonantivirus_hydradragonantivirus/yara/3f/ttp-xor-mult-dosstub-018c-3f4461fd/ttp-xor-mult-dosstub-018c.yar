rule TTP_XOR_MULT_DOSStub_018c {
  strings:
    $key_018c = { 55 e4 [2] 21 fc [2] 66 fe [2] 21 ef [2] 6f e3 [2] 63 e9 [2] 74 e2 [2] 6f ac [2] 52 }

  condition:
    any of them
}