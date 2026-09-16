rule TTP_XOR_MULT_DOSStub_c010 {
  strings:
    $key_c010 = { 94 78 [2] e0 60 [2] a7 62 [2] e0 73 [2] ae 7f [2] a2 75 [2] b5 7e [2] ae 30 [2] 93 }

  condition:
    any of them
}