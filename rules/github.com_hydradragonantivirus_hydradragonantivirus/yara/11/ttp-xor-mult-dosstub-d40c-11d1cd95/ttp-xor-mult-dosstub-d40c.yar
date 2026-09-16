rule TTP_XOR_MULT_DOSStub_d40c {
  strings:
    $key_d40c = { 80 64 [2] f4 7c [2] b3 7e [2] f4 6f [2] ba 63 [2] b6 69 [2] a1 62 [2] ba 2c [2] 87 }

  condition:
    any of them
}