rule TTP_XOR_MULT_DOSStub_548c {
  strings:
    $key_548c = { 00 e4 [2] 74 fc [2] 33 fe [2] 74 ef [2] 3a e3 [2] 36 e9 [2] 21 e2 [2] 3a ac [2] 07 }

  condition:
    any of them
}