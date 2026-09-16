rule TTP_XOR_MULT_DOSStub_d3ee {
  strings:
    $key_d3ee = { 87 86 [2] f3 9e [2] b4 9c [2] f3 8d [2] bd 81 [2] b1 8b [2] a6 80 [2] bd ce [2] 80 }

  condition:
    any of them
}