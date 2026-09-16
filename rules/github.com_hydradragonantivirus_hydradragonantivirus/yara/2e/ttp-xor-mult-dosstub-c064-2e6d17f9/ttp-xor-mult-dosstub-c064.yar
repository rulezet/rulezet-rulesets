rule TTP_XOR_MULT_DOSStub_c064 {
  strings:
    $key_c064 = { 94 0c [2] e0 14 [2] a7 16 [2] e0 07 [2] ae 0b [2] a2 01 [2] b5 0a [2] ae 44 [2] 93 }

  condition:
    any of them
}