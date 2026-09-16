rule TTP_XOR_MULT_DOSStub_dd59 {
  strings:
    $key_dd59 = { 89 31 [2] fd 29 [2] ba 2b [2] fd 3a [2] b3 36 [2] bf 3c [2] a8 37 [2] b3 79 [2] 8e }

  condition:
    any of them
}