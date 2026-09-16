rule TTP_XOR_MULT_DOSStub_d3e8 {
  strings:
    $key_d3e8 = { 87 80 [2] f3 98 [2] b4 9a [2] f3 8b [2] bd 87 [2] b1 8d [2] a6 86 [2] bd c8 [2] 80 }

  condition:
    any of them
}