rule TTP_XOR_MULT_DOSStub_c179 {
  strings:
    $key_c179 = { 95 11 [2] e1 09 [2] a6 0b [2] e1 1a [2] af 16 [2] a3 1c [2] b4 17 [2] af 59 [2] 92 }

  condition:
    any of them
}