rule TTP_XOR_MULT_DOSStub_dd5e {
  strings:
    $key_dd5e = { 89 36 [2] fd 2e [2] ba 2c [2] fd 3d [2] b3 31 [2] bf 3b [2] a8 30 [2] b3 7e [2] 8e }

  condition:
    any of them
}