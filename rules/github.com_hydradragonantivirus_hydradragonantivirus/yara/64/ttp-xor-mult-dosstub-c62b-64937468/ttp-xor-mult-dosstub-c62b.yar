rule TTP_XOR_MULT_DOSStub_c62b {
  strings:
    $key_c62b = { 92 43 [2] e6 5b [2] a1 59 [2] e6 48 [2] a8 44 [2] a4 4e [2] b3 45 [2] a8 0b [2] 95 }

  condition:
    any of them
}