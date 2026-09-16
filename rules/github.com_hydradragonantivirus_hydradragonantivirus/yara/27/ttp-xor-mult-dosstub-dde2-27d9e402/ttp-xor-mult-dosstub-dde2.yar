rule TTP_XOR_MULT_DOSStub_dde2 {
  strings:
    $key_dde2 = { 89 8a [2] fd 92 [2] ba 90 [2] fd 81 [2] b3 8d [2] bf 87 [2] a8 8c [2] b3 c2 [2] 8e }

  condition:
    any of them
}