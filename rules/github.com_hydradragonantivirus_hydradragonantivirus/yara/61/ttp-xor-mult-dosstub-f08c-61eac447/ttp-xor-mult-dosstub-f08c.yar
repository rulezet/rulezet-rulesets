rule TTP_XOR_MULT_DOSStub_f08c {
  strings:
    $key_f08c = { a4 e4 [2] d0 fc [2] 97 fe [2] d0 ef [2] 9e e3 [2] 92 e9 [2] 85 e2 [2] 9e ac [2] a3 }

  condition:
    any of them
}