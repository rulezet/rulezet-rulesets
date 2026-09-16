rule TTP_XOR_MULT_DOSStub_f38a {
  strings:
    $key_f38a = { a7 e2 [2] d3 fa [2] 94 f8 [2] d3 e9 [2] 9d e5 [2] 91 ef [2] 86 e4 [2] 9d aa [2] a0 }

  condition:
    any of them
}