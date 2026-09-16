rule TTP_XOR_MULT_DOSStub_ddf2 {
  strings:
    $key_ddf2 = { 89 9a [2] fd 82 [2] ba 80 [2] fd 91 [2] b3 9d [2] bf 97 [2] a8 9c [2] b3 d2 [2] 8e }

  condition:
    any of them
}