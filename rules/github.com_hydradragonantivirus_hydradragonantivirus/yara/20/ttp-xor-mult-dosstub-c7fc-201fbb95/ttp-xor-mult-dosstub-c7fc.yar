rule TTP_XOR_MULT_DOSStub_c7fc {
  strings:
    $key_c7fc = { 93 94 [2] e7 8c [2] a0 8e [2] e7 9f [2] a9 93 [2] a5 99 [2] b2 92 [2] a9 dc [2] 94 }

  condition:
    any of them
}