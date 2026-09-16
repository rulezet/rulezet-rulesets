rule TTP_XOR_MULT_DOSStub_c18a {
  strings:
    $key_c18a = { 95 e2 [2] e1 fa [2] a6 f8 [2] e1 e9 [2] af e5 [2] a3 ef [2] b4 e4 [2] af aa [2] 92 }

  condition:
    any of them
}