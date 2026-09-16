rule TTP_XOR_MULT_DOSStub_dd55 {
  strings:
    $key_dd55 = { 89 3d [2] fd 25 [2] ba 27 [2] fd 36 [2] b3 3a [2] bf 30 [2] a8 3b [2] b3 75 [2] 8e }

  condition:
    any of them
}