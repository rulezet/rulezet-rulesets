rule TTP_XOR_MULT_DOSStub_318c {
  strings:
    $key_318c = { 65 e4 [2] 11 fc [2] 56 fe [2] 11 ef [2] 5f e3 [2] 53 e9 [2] 44 e2 [2] 5f ac [2] 62 }

  condition:
    any of them
}