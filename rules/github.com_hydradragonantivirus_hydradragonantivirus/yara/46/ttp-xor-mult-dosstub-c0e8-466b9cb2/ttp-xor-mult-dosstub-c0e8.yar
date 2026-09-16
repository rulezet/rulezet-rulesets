rule TTP_XOR_MULT_DOSStub_c0e8 {
  strings:
    $key_c0e8 = { 94 80 [2] e0 98 [2] a7 9a [2] e0 8b [2] ae 87 [2] a2 8d [2] b5 86 [2] ae c8 [2] 93 }

  condition:
    any of them
}