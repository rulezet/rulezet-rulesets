rule TTP_XOR_MULT_DOSStub_c7e3 {
  strings:
    $key_c7e3 = { 93 8b [2] e7 93 [2] a0 91 [2] e7 80 [2] a9 8c [2] a5 86 [2] b2 8d [2] a9 c3 [2] 94 }

  condition:
    any of them
}