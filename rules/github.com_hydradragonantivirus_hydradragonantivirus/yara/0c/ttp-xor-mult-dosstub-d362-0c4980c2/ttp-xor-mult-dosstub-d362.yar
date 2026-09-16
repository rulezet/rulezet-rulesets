rule TTP_XOR_MULT_DOSStub_d362 {
  strings:
    $key_d362 = { 87 0a [2] f3 12 [2] b4 10 [2] f3 01 [2] bd 0d [2] b1 07 [2] a6 0c [2] bd 42 [2] 80 }

  condition:
    any of them
}