rule TTP_XOR_MULT_DOSStub_d443 {
  strings:
    $key_d443 = { 80 2b [2] f4 33 [2] b3 31 [2] f4 20 [2] ba 2c [2] b6 26 [2] a1 2d [2] ba 63 [2] 87 }

  condition:
    any of them
}