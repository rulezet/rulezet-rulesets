rule TTP_XOR_MULT_DOSStub_dd53 {
  strings:
    $key_dd53 = { 89 3b [2] fd 23 [2] ba 21 [2] fd 30 [2] b3 3c [2] bf 36 [2] a8 3d [2] b3 73 [2] 8e }

  condition:
    any of them
}