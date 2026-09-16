rule TTP_XOR_MULT_DOSStub_d376 {
  strings:
    $key_d376 = { 87 1e [2] f3 06 [2] b4 04 [2] f3 15 [2] bd 19 [2] b1 13 [2] a6 18 [2] bd 56 [2] 80 }

  condition:
    any of them
}