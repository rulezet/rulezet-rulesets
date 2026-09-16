rule TTP_XOR_MULT_DOSStub_d46b {
  strings:
    $key_d46b = { 80 03 [2] f4 1b [2] b3 19 [2] f4 08 [2] ba 04 [2] b6 0e [2] a1 05 [2] ba 4b [2] 87 }

  condition:
    any of them
}