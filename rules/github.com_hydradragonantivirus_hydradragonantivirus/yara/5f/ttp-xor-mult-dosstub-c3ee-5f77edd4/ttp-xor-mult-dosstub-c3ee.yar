rule TTP_XOR_MULT_DOSStub_c3ee {
  strings:
    $key_c3ee = { 97 86 [2] e3 9e [2] a4 9c [2] e3 8d [2] ad 81 [2] a1 8b [2] b6 80 [2] ad ce [2] 90 }

  condition:
    any of them
}