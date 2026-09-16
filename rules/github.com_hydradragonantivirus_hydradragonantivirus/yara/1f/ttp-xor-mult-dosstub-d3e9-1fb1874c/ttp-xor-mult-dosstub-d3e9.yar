rule TTP_XOR_MULT_DOSStub_d3e9 {
  strings:
    $key_d3e9 = { 87 81 [2] f3 99 [2] b4 9b [2] f3 8a [2] bd 86 [2] b1 8c [2] a6 87 [2] bd c9 [2] 80 }

  condition:
    any of them
}