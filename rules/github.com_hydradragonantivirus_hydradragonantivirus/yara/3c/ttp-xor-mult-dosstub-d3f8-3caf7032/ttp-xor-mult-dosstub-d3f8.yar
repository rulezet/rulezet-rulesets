rule TTP_XOR_MULT_DOSStub_d3f8 {
  strings:
    $key_d3f8 = { 87 90 [2] f3 88 [2] b4 8a [2] f3 9b [2] bd 97 [2] b1 9d [2] a6 96 [2] bd d8 [2] 80 }

  condition:
    any of them
}