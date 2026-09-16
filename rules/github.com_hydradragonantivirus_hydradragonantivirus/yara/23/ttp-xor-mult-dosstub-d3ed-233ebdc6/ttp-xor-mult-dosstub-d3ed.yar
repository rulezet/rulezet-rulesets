rule TTP_XOR_MULT_DOSStub_d3ed {
  strings:
    $key_d3ed = { 87 85 [2] f3 9d [2] b4 9f [2] f3 8e [2] bd 82 [2] b1 88 [2] a6 83 [2] bd cd [2] 80 }

  condition:
    any of them
}