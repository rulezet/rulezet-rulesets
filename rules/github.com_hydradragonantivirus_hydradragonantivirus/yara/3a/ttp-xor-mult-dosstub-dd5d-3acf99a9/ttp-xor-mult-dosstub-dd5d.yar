rule TTP_XOR_MULT_DOSStub_dd5d {
  strings:
    $key_dd5d = { 89 35 [2] fd 2d [2] ba 2f [2] fd 3e [2] b3 32 [2] bf 38 [2] a8 33 [2] b3 7d [2] 8e }

  condition:
    any of them
}