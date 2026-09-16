rule TTP_XOR_MULT_DOSStub_dd3a {
  strings:
    $key_dd3a = { 89 52 [2] fd 4a [2] ba 48 [2] fd 59 [2] b3 55 [2] bf 5f [2] a8 54 [2] b3 1a [2] 8e }

  condition:
    any of them
}