rule TTP_XOR_MULT_DOSStub_c729 {
  strings:
    $key_c729 = { 93 41 [2] e7 59 [2] a0 5b [2] e7 4a [2] a9 46 [2] a5 4c [2] b2 47 [2] a9 09 [2] 94 }

  condition:
    any of them
}