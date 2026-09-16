rule TTP_XOR_MULT_DOSStub_dd49 {
  strings:
    $key_dd49 = { 89 21 [2] fd 39 [2] ba 3b [2] fd 2a [2] b3 26 [2] bf 2c [2] a8 27 [2] b3 69 [2] 8e }

  condition:
    any of them
}