rule TTP_XOR_MULT_DOSStub_c48a {
  strings:
    $key_c48a = { 90 e2 [2] e4 fa [2] a3 f8 [2] e4 e9 [2] aa e5 [2] a6 ef [2] b1 e4 [2] aa aa [2] 97 }

  condition:
    any of them
}