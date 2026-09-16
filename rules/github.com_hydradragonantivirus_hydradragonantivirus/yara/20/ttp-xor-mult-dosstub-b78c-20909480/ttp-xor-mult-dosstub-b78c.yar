rule TTP_XOR_MULT_DOSStub_b78c {
  strings:
    $key_b78c = { e3 e4 [2] 97 fc [2] d0 fe [2] 97 ef [2] d9 e3 [2] d5 e9 [2] c2 e2 [2] d9 ac [2] e4 }

  condition:
    any of them
}