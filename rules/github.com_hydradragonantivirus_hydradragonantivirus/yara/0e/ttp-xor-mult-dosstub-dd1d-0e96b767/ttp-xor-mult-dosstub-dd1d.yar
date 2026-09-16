rule TTP_XOR_MULT_DOSStub_dd1d {
  strings:
    $key_dd1d = { 89 75 [2] fd 6d [2] ba 6f [2] fd 7e [2] b3 72 [2] bf 78 [2] a8 73 [2] b3 3d [2] 8e }

  condition:
    any of them
}