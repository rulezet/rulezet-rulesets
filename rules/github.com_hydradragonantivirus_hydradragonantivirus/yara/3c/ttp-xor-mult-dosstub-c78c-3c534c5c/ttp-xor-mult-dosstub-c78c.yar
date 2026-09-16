rule TTP_XOR_MULT_DOSStub_c78c {
  strings:
    $key_c78c = { 93 e4 [2] e7 fc [2] a0 fe [2] e7 ef [2] a9 e3 [2] a5 e9 [2] b2 e2 [2] a9 ac [2] 94 }

  condition:
    any of them
}