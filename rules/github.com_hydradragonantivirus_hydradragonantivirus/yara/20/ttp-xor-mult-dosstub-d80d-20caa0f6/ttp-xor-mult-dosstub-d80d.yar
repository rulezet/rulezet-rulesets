rule TTP_XOR_MULT_DOSStub_d80d {
  strings:
    $key_d80d = { 8c 65 [2] f8 7d [2] bf 7f [2] f8 6e [2] b6 62 [2] ba 68 [2] ad 63 [2] b6 2d [2] 8b }

  condition:
    any of them
}