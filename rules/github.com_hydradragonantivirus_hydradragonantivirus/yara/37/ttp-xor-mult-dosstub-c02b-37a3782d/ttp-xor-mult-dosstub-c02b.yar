rule TTP_XOR_MULT_DOSStub_c02b {
  strings:
    $key_c02b = { 94 43 [2] e0 5b [2] a7 59 [2] e0 48 [2] ae 44 [2] a2 4e [2] b5 45 [2] ae 0b [2] 93 }

  condition:
    any of them
}