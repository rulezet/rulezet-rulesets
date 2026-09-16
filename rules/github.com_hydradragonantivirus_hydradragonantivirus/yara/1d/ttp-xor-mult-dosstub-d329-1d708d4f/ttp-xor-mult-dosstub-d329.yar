rule TTP_XOR_MULT_DOSStub_d329 {
  strings:
    $key_d329 = { 87 41 [2] f3 59 [2] b4 5b [2] f3 4a [2] bd 46 [2] b1 4c [2] a6 47 [2] bd 09 [2] 80 }

  condition:
    any of them
}