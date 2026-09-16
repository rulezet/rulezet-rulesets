rule TTP_XOR_MULT_DOSStub_c33e {
  strings:
    $key_c33e = { 97 56 [2] e3 4e [2] a4 4c [2] e3 5d [2] ad 51 [2] a1 5b [2] b6 50 [2] ad 1e [2] 90 }

  condition:
    any of them
}