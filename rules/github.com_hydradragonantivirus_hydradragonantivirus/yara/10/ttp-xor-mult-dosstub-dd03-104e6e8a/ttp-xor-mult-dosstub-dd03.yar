rule TTP_XOR_MULT_DOSStub_dd03 {
  strings:
    $key_dd03 = { 89 6b [2] fd 73 [2] ba 71 [2] fd 60 [2] b3 6c [2] bf 66 [2] a8 6d [2] b3 23 [2] 8e }

  condition:
    any of them
}