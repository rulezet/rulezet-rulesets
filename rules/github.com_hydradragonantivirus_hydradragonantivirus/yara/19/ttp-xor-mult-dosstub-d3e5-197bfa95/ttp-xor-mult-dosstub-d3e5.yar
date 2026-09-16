rule TTP_XOR_MULT_DOSStub_d3e5 {
  strings:
    $key_d3e5 = { 87 8d [2] f3 95 [2] b4 97 [2] f3 86 [2] bd 8a [2] b1 80 [2] a6 8b [2] bd c5 [2] 80 }

  condition:
    any of them
}