rule TTP_XOR_MULT_DOSStub_268c {
  strings:
    $key_268c = { 72 e4 [2] 06 fc [2] 41 fe [2] 06 ef [2] 48 e3 [2] 44 e9 [2] 53 e2 [2] 48 ac [2] 75 }

  condition:
    any of them
}