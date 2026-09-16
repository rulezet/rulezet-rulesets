rule TTP_XOR_MULT_DOSStub_c07b {
  strings:
    $key_c07b = { 94 13 [2] e0 0b [2] a7 09 [2] e0 18 [2] ae 14 [2] a2 1e [2] b5 15 [2] ae 5b [2] 93 }

  condition:
    any of them
}