rule TTP_XOR_MULT_DOSStub_dd4a {
  strings:
    $key_dd4a = { 89 22 [2] fd 3a [2] ba 38 [2] fd 29 [2] b3 25 [2] bf 2f [2] a8 24 [2] b3 6a [2] 8e }

  condition:
    any of them
}