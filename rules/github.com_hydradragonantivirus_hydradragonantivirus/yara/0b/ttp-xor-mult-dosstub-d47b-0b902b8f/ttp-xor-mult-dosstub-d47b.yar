rule TTP_XOR_MULT_DOSStub_d47b {
  strings:
    $key_d47b = { 80 13 [2] f4 0b [2] b3 09 [2] f4 18 [2] ba 14 [2] b6 1e [2] a1 15 [2] ba 5b [2] 87 }

  condition:
    any of them
}