rule TTP_XOR_MULT_DOSStub_d3ff {
  strings:
    $key_d3ff = { 87 97 [2] f3 8f [2] b4 8d [2] f3 9c [2] bd 90 [2] b1 9a [2] a6 91 [2] bd df [2] 80 }

  condition:
    any of them
}