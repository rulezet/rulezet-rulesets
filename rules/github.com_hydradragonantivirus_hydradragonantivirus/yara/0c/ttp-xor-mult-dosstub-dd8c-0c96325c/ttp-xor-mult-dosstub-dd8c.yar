rule TTP_XOR_MULT_DOSStub_dd8c {
  strings:
    $key_dd8c = { 89 e4 [2] fd fc [2] ba fe [2] fd ef [2] b3 e3 [2] bf e9 [2] a8 e2 [2] b3 ac [2] 8e }

  condition:
    any of them
}