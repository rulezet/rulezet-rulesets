rule TTP_XOR_MULT_DOSStub_c07c {
  strings:
    $key_c07c = { 94 14 [2] e0 0c [2] a7 0e [2] e0 1f [2] ae 13 [2] a2 19 [2] b5 12 [2] ae 5c [2] 93 }

  condition:
    any of them
}