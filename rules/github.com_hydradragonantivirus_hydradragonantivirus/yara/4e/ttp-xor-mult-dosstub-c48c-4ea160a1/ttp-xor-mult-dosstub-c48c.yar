rule TTP_XOR_MULT_DOSStub_c48c {
  strings:
    $key_c48c = { 90 e4 [2] e4 fc [2] a3 fe [2] e4 ef [2] aa e3 [2] a6 e9 [2] b1 e2 [2] aa ac [2] 97 }

  condition:
    any of them
}