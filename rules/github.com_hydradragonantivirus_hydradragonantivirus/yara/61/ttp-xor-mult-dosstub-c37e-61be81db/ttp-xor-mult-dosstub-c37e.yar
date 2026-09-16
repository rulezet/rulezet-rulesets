rule TTP_XOR_MULT_DOSStub_c37e {
  strings:
    $key_c37e = { 97 16 [2] e3 0e [2] a4 0c [2] e3 1d [2] ad 11 [2] a1 1b [2] b6 10 [2] ad 5e [2] 90 }

  condition:
    any of them
}