rule TTP_XOR_MULT_DOSStub_dd45 {
  strings:
    $key_dd45 = { 89 2d [2] fd 35 [2] ba 37 [2] fd 26 [2] b3 2a [2] bf 20 [2] a8 2b [2] b3 65 [2] 8e }

  condition:
    any of them
}