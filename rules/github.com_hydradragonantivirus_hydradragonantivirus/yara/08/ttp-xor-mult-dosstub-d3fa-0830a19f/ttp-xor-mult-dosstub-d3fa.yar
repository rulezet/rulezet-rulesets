rule TTP_XOR_MULT_DOSStub_d3fa {
  strings:
    $key_d3fa = { 87 92 [2] f3 8a [2] b4 88 [2] f3 99 [2] bd 95 [2] b1 9f [2] a6 94 [2] bd da [2] 80 }

  condition:
    any of them
}