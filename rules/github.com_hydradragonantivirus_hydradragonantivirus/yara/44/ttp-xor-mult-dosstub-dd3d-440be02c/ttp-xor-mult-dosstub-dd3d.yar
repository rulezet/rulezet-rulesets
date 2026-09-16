rule TTP_XOR_MULT_DOSStub_dd3d {
  strings:
    $key_dd3d = { 89 55 [2] fd 4d [2] ba 4f [2] fd 5e [2] b3 52 [2] bf 58 [2] a8 53 [2] b3 1d [2] 8e }

  condition:
    any of them
}