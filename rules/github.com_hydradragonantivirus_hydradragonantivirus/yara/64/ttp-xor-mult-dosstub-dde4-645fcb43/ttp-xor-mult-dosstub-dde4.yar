rule TTP_XOR_MULT_DOSStub_dde4 {
  strings:
    $key_dde4 = { 89 8c [2] fd 94 [2] ba 96 [2] fd 87 [2] b3 8b [2] bf 81 [2] a8 8a [2] b3 c4 [2] 8e }

  condition:
    any of them
}