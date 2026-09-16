rule TTP_XOR_MULT_DOSStub_d35f {
  strings:
    $key_d35f = { 87 37 [2] f3 2f [2] b4 2d [2] f3 3c [2] bd 30 [2] b1 3a [2] a6 31 [2] bd 7f [2] 80 }

  condition:
    any of them
}