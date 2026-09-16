rule TTP_XOR_MULT_DOSStub_ddf0 {
  strings:
    $key_ddf0 = { 89 98 [2] fd 80 [2] ba 82 [2] fd 93 [2] b3 9f [2] bf 95 [2] a8 9e [2] b3 d0 [2] 8e }

  condition:
    any of them
}