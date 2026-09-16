rule TTP_XOR_MULT_DOSStub_dd7a {
  strings:
    $key_dd7a = { 89 12 [2] fd 0a [2] ba 08 [2] fd 19 [2] b3 15 [2] bf 1f [2] a8 14 [2] b3 5a [2] 8e }

  condition:
    any of them
}