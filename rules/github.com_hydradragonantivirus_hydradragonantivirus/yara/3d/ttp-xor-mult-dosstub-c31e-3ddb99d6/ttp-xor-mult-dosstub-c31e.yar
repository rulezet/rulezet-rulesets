rule TTP_XOR_MULT_DOSStub_c31e {
  strings:
    $key_c31e = { 97 76 [2] e3 6e [2] a4 6c [2] e3 7d [2] ad 71 [2] a1 7b [2] b6 70 [2] ad 3e [2] 90 }

  condition:
    any of them
}