rule TTP_XOR_MULT_DOSStub_d3fc {
  strings:
    $key_d3fc = { 87 94 [2] f3 8c [2] b4 8e [2] f3 9f [2] bd 93 [2] b1 99 [2] a6 92 [2] bd dc [2] 80 }

  condition:
    any of them
}