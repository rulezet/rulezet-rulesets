rule TTP_XOR_MULT_DOSStub_a78c {
  strings:
    $key_a78c = { f3 e4 [2] 87 fc [2] c0 fe [2] 87 ef [2] c9 e3 [2] c5 e9 [2] d2 e2 [2] c9 ac [2] f4 }

  condition:
    any of them
}