rule TTP_XOR_MULT_DOSStub_d327 {
  strings:
    $key_d327 = { 87 4f [2] f3 57 [2] b4 55 [2] f3 44 [2] bd 48 [2] b1 42 [2] a6 49 [2] bd 07 [2] 80 }

  condition:
    any of them
}