rule TTP_XOR_MULT_DOSStub_d36d {
  strings:
    $key_d36d = { 87 05 [2] f3 1d [2] b4 1f [2] f3 0e [2] bd 02 [2] b1 08 [2] a6 03 [2] bd 4d [2] 80 }

  condition:
    any of them
}