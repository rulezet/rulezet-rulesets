rule TTP_XOR_MULT_DOSStub_c66c {
  strings:
    $key_c66c = { 92 04 [2] e6 1c [2] a1 1e [2] e6 0f [2] a8 03 [2] a4 09 [2] b3 02 [2] a8 4c [2] 95 }

  condition:
    any of them
}