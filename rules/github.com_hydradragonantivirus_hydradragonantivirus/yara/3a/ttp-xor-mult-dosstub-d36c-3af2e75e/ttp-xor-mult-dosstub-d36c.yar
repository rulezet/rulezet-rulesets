rule TTP_XOR_MULT_DOSStub_d36c {
  strings:
    $key_d36c = { 87 04 [2] f3 1c [2] b4 1e [2] f3 0f [2] bd 03 [2] b1 09 [2] a6 02 [2] bd 4c [2] 80 }

  condition:
    any of them
}