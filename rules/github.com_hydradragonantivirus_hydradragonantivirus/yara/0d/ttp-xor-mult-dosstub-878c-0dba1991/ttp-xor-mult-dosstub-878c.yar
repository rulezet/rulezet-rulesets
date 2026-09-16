rule TTP_XOR_MULT_DOSStub_878c {
  strings:
    $key_878c = { d3 e4 [2] a7 fc [2] e0 fe [2] a7 ef [2] e9 e3 [2] e5 e9 [2] f2 e2 [2] e9 ac [2] d4 }

  condition:
    any of them
}