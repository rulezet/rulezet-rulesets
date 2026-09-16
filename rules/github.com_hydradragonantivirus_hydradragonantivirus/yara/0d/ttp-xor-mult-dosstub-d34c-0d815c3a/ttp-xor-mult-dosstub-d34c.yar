rule TTP_XOR_MULT_DOSStub_d34c {
  strings:
    $key_d34c = { 87 24 [2] f3 3c [2] b4 3e [2] f3 2f [2] bd 23 [2] b1 29 [2] a6 22 [2] bd 6c [2] 80 }

  condition:
    any of them
}