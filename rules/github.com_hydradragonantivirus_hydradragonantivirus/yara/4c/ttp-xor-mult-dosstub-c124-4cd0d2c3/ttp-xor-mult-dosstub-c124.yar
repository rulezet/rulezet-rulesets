rule TTP_XOR_MULT_DOSStub_c124 {
  strings:
    $key_c124 = { 95 4c [2] e1 54 [2] a6 56 [2] e1 47 [2] af 4b [2] a3 41 [2] b4 4a [2] af 04 [2] 92 }

  condition:
    any of them
}