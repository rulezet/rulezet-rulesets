rule TTP_XOR_MULT_DOSStub_678c {
  strings:
    $key_678c = { 33 e4 [2] 47 fc [2] 00 fe [2] 47 ef [2] 09 e3 [2] 05 e9 [2] 12 e2 [2] 09 ac [2] 34 }

  condition:
    any of them
}