rule TTP_XOR_MULT_DOSStub_618c {
  strings:
    $key_618c = { 35 e4 [2] 41 fc [2] 06 fe [2] 41 ef [2] 0f e3 [2] 03 e9 [2] 14 e2 [2] 0f ac [2] 32 }

  condition:
    any of them
}