rule TTP_XOR_MULT_DOSStub_c079 {
  strings:
    $key_c079 = { 94 11 [2] e0 09 [2] a7 0b [2] e0 1a [2] ae 16 [2] a2 1c [2] b5 17 [2] ae 59 [2] 93 }

  condition:
    any of them
}