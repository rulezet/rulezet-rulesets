rule TTP_XOR_MULT_DOSStub_dd2a {
  strings:
    $key_dd2a = { 89 42 [2] fd 5a [2] ba 58 [2] fd 49 [2] b3 45 [2] bf 4f [2] a8 44 [2] b3 0a [2] 8e }

  condition:
    any of them
}