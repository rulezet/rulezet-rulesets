rule TTP_XOR_MULT_DOSStub_d3fd {
  strings:
    $key_d3fd = { 87 95 [2] f3 8d [2] b4 8f [2] f3 9e [2] bd 92 [2] b1 98 [2] a6 93 [2] bd dd [2] 80 }

  condition:
    any of them
}