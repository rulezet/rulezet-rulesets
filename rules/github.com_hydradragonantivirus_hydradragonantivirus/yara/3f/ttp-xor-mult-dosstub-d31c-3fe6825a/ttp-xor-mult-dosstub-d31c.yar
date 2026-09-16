rule TTP_XOR_MULT_DOSStub_d31c {
  strings:
    $key_d31c = { 87 74 [2] f3 6c [2] b4 6e [2] f3 7f [2] bd 73 [2] b1 79 [2] a6 72 [2] bd 3c [2] 80 }

  condition:
    any of them
}