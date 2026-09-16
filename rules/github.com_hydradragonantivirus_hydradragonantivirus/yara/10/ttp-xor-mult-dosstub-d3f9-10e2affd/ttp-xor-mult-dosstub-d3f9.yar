rule TTP_XOR_MULT_DOSStub_d3f9 {
  strings:
    $key_d3f9 = { 87 91 [2] f3 89 [2] b4 8b [2] f3 9a [2] bd 96 [2] b1 9c [2] a6 97 [2] bd d9 [2] 80 }

  condition:
    any of them
}