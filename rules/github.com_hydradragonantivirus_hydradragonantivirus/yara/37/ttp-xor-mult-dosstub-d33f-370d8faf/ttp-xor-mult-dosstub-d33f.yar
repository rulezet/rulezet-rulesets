rule TTP_XOR_MULT_DOSStub_d33f {
  strings:
    $key_d33f = { 87 57 [2] f3 4f [2] b4 4d [2] f3 5c [2] bd 50 [2] b1 5a [2] a6 51 [2] bd 1f [2] 80 }

  condition:
    any of them
}