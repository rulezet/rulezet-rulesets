rule TTP_XOR_MULT_DOSStub_dd5a {
  strings:
    $key_dd5a = { 89 32 [2] fd 2a [2] ba 28 [2] fd 39 [2] b3 35 [2] bf 3f [2] a8 34 [2] b3 7a [2] 8e }

  condition:
    any of them
}