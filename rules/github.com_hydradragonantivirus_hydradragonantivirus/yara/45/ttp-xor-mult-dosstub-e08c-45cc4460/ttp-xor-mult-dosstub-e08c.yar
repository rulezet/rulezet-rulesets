rule TTP_XOR_MULT_DOSStub_e08c {
  strings:
    $key_e08c = { b4 e4 [2] c0 fc [2] 87 fe [2] c0 ef [2] 8e e3 [2] 82 e9 [2] 95 e2 [2] 8e ac [2] b3 }

  condition:
    any of them
}