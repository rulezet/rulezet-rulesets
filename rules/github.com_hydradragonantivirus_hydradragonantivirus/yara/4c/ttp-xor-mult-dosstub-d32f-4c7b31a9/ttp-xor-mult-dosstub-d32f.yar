rule TTP_XOR_MULT_DOSStub_d32f {
  strings:
    $key_d32f = { 87 47 [2] f3 5f [2] b4 5d [2] f3 4c [2] bd 40 [2] b1 4a [2] a6 41 [2] bd 0f [2] 80 }

  condition:
    any of them
}