rule TTP_XOR_MULT_DOSStub_c02e {
  strings:
    $key_c02e = { 94 46 [2] e0 5e [2] a7 5c [2] e0 4d [2] ae 41 [2] a2 4b [2] b5 40 [2] ae 0e [2] 93 }

  condition:
    any of them
}