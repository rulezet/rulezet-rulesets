rule TTP_XOR_MULT_DOSStub_d81d {
  strings:
    $key_d81d = { 8c 75 [2] f8 6d [2] bf 6f [2] f8 7e [2] b6 72 [2] ba 78 [2] ad 73 [2] b6 3d [2] 8b }

  condition:
    any of them
}