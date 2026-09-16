rule TTP_XOR_MULT_DOSStub_c05c {
  strings:
    $key_c05c = { 94 34 [2] e0 2c [2] a7 2e [2] e0 3f [2] ae 33 [2] a2 39 [2] b5 32 [2] ae 7c [2] 93 }

  condition:
    any of them
}