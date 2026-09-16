rule TTP_XOR_MULT_DOSStub_dd58 {
  strings:
    $key_dd58 = { 89 30 [2] fd 28 [2] ba 2a [2] fd 3b [2] b3 37 [2] bf 3d [2] a8 36 [2] b3 78 [2] 8e }

  condition:
    any of them
}