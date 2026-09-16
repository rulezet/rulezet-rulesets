rule TTP_XOR_MULT_DOSStub_a68c {
  strings:
    $key_a68c = { f2 e4 [2] 86 fc [2] c1 fe [2] 86 ef [2] c8 e3 [2] c4 e9 [2] d3 e2 [2] c8 ac [2] f5 }

  condition:
    any of them
}