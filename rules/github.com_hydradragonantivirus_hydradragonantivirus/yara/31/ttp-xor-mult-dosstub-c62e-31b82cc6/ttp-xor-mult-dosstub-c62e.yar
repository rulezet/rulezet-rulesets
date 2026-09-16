rule TTP_XOR_MULT_DOSStub_c62e {
  strings:
    $key_c62e = { 92 46 [2] e6 5e [2] a1 5c [2] e6 4d [2] a8 41 [2] a4 4b [2] b3 40 [2] a8 0e [2] 95 }

  condition:
    any of them
}