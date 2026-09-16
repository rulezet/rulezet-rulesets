rule TTP_XOR_MULT_DOSStub_d35e {
  strings:
    $key_d35e = { 87 36 [2] f3 2e [2] b4 2c [2] f3 3d [2] bd 31 [2] b1 3b [2] a6 30 [2] bd 7e [2] 80 }

  condition:
    any of them
}