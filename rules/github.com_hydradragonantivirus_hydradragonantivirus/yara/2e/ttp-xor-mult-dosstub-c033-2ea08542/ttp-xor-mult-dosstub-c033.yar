rule TTP_XOR_MULT_DOSStub_c033 {
  strings:
    $key_c033 = { 94 5b [2] e0 43 [2] a7 41 [2] e0 50 [2] ae 5c [2] a2 56 [2] b5 5d [2] ae 13 [2] 93 }

  condition:
    any of them
}