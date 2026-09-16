rule TTP_XOR_MULT_DOSStub_d371 {
  strings:
    $key_d371 = { 87 19 [2] f3 01 [2] b4 03 [2] f3 12 [2] bd 1e [2] b1 14 [2] a6 1f [2] bd 51 [2] 80 }

  condition:
    any of them
}