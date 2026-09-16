rule TTP_XOR_MULT_DOSStub_d10d {
  strings:
    $key_d10d = { 85 65 [2] f1 7d [2] b6 7f [2] f1 6e [2] bf 62 [2] b3 68 [2] a4 63 [2] bf 2d [2] 82 }

  condition:
    any of them
}