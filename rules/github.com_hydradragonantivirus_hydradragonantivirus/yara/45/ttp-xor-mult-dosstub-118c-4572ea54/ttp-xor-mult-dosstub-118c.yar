rule TTP_XOR_MULT_DOSStub_118c {
  strings:
    $key_118c = { 45 e4 [2] 31 fc [2] 76 fe [2] 31 ef [2] 7f e3 [2] 73 e9 [2] 64 e2 [2] 7f ac [2] 42 }

  condition:
    any of them
}