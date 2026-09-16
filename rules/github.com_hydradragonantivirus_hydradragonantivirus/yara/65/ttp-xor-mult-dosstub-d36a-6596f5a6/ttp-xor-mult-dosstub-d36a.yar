rule TTP_XOR_MULT_DOSStub_d36a {
  strings:
    $key_d36a = { 87 02 [2] f3 1a [2] b4 18 [2] f3 09 [2] bd 05 [2] b1 0f [2] a6 04 [2] bd 4a [2] 80 }

  condition:
    any of them
}