rule TTP_XOR_MULT_DOSStub_c265 {
  strings:
    $key_c265 = { 96 0d [2] e2 15 [2] a5 17 [2] e2 06 [2] ac 0a [2] a0 00 [2] b7 0b [2] ac 45 [2] 91 }

  condition:
    any of them
}