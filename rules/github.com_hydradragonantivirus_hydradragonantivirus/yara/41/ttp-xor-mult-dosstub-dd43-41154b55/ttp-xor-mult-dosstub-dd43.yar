rule TTP_XOR_MULT_DOSStub_dd43 {
  strings:
    $key_dd43 = { 89 2b [2] fd 33 [2] ba 31 [2] fd 20 [2] b3 2c [2] bf 26 [2] a8 2d [2] b3 63 [2] 8e }

  condition:
    any of them
}