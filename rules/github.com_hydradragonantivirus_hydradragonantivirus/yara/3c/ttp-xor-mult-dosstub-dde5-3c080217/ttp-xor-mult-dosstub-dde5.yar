rule TTP_XOR_MULT_DOSStub_dde5 {
  strings:
    $key_dde5 = { 89 8d [2] fd 95 [2] ba 97 [2] fd 86 [2] b3 8a [2] bf 80 [2] a8 8b [2] b3 c5 [2] 8e }

  condition:
    any of them
}