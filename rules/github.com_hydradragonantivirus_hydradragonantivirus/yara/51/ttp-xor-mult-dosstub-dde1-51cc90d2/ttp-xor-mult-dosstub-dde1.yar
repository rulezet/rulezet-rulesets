rule TTP_XOR_MULT_DOSStub_dde1 {
  strings:
    $key_dde1 = { 89 89 [2] fd 91 [2] ba 93 [2] fd 82 [2] b3 8e [2] bf 84 [2] a8 8f [2] b3 c1 [2] 8e }

  condition:
    any of them
}