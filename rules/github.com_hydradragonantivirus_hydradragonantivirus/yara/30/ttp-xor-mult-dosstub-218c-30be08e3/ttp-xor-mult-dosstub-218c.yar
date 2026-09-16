rule TTP_XOR_MULT_DOSStub_218c {
  strings:
    $key_218c = { 75 e4 [2] 01 fc [2] 46 fe [2] 01 ef [2] 4f e3 [2] 43 e9 [2] 54 e2 [2] 4f ac [2] 72 }

  condition:
    any of them
}