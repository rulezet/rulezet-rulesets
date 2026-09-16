rule TTP_XOR_MULT_DOSStub_c66e {
  strings:
    $key_c66e = { 92 06 [2] e6 1e [2] a1 1c [2] e6 0d [2] a8 01 [2] a4 0b [2] b3 00 [2] a8 4e [2] 95 }

  condition:
    any of them
}