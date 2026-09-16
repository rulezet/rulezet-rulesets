rule TTP_XOR_MULT_DOSStub_dd8a {
  strings:
    $key_dd8a = { 89 e2 [2] fd fa [2] ba f8 [2] fd e9 [2] b3 e5 [2] bf ef [2] a8 e4 [2] b3 aa [2] 8e }

  condition:
    any of them
}