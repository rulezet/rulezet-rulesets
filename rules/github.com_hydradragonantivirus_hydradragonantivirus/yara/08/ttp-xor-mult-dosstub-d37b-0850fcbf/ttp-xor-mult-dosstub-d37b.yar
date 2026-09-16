rule TTP_XOR_MULT_DOSStub_d37b {
  strings:
    $key_d37b = { 87 13 [2] f3 0b [2] b4 09 [2] f3 18 [2] bd 14 [2] b1 1e [2] a6 15 [2] bd 5b [2] 80 }

  condition:
    any of them
}