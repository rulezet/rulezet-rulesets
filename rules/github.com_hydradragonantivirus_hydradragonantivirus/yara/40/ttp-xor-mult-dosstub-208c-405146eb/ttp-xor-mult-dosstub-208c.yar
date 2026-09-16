rule TTP_XOR_MULT_DOSStub_208c {
  strings:
    $key_208c = { 74 e4 [2] 00 fc [2] 47 fe [2] 00 ef [2] 4e e3 [2] 42 e9 [2] 55 e2 [2] 4e ac [2] 73 }

  condition:
    any of them
}