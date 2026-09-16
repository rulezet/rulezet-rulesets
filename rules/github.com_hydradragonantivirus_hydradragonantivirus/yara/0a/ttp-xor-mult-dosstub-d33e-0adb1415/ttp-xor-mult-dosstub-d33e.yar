rule TTP_XOR_MULT_DOSStub_d33e {
  strings:
    $key_d33e = { 87 56 [2] f3 4e [2] b4 4c [2] f3 5d [2] bd 51 [2] b1 5b [2] a6 50 [2] bd 1e [2] 80 }

  condition:
    any of them
}