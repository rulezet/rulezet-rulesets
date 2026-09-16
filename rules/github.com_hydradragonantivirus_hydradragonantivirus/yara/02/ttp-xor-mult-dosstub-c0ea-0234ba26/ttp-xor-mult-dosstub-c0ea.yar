rule TTP_XOR_MULT_DOSStub_c0ea {
  strings:
    $key_c0ea = { 94 82 [2] e0 9a [2] a7 98 [2] e0 89 [2] ae 85 [2] a2 8f [2] b5 84 [2] ae ca [2] 93 }

  condition:
    any of them
}