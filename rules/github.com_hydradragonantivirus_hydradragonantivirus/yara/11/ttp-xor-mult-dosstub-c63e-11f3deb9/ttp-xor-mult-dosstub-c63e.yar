rule TTP_XOR_MULT_DOSStub_c63e {
  strings:
    $key_c63e = { 92 56 [2] e6 4e [2] a1 4c [2] e6 5d [2] a8 51 [2] a4 5b [2] b3 50 [2] a8 1e [2] 95 }

  condition:
    any of them
}