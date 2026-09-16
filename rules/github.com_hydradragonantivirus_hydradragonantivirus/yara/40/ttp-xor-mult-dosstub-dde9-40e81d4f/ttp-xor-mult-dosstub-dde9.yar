rule TTP_XOR_MULT_DOSStub_dde9 {
  strings:
    $key_dde9 = { 89 81 [2] fd 99 [2] ba 9b [2] fd 8a [2] b3 86 [2] bf 8c [2] a8 87 [2] b3 c9 [2] 8e }

  condition:
    any of them
}