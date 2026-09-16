rule TTP_XOR_MULT_DOSStub_c6ee {
  strings:
    $key_c6ee = { 92 86 [2] e6 9e [2] a1 9c [2] e6 8d [2] a8 81 [2] a4 8b [2] b3 80 [2] a8 ce [2] 95 }

  condition:
    any of them
}