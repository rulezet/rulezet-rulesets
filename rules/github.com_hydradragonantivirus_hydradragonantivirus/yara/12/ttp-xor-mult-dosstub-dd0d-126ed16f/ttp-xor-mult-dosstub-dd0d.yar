rule TTP_XOR_MULT_DOSStub_dd0d {
  strings:
    $key_dd0d = { 89 65 [2] fd 7d [2] ba 7f [2] fd 6e [2] b3 62 [2] bf 68 [2] a8 63 [2] b3 2d [2] 8e }

  condition:
    any of them
}