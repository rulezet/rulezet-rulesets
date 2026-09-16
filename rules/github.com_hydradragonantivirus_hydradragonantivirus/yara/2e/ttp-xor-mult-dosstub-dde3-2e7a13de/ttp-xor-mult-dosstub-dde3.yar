rule TTP_XOR_MULT_DOSStub_dde3 {
  strings:
    $key_dde3 = { 89 8b [2] fd 93 [2] ba 91 [2] fd 80 [2] b3 8c [2] bf 86 [2] a8 8d [2] b3 c3 [2] 8e }

  condition:
    any of them
}