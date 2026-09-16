rule TTP_XOR_MULT_DOSStub_c169 {
  strings:
    $key_c169 = { 95 01 [2] e1 19 [2] a6 1b [2] e1 0a [2] af 06 [2] a3 0c [2] b4 07 [2] af 49 [2] 92 }

  condition:
    any of them
}