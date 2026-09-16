rule TTP_XOR_MULT_DOSStub_c133 {
  strings:
    $key_c133 = { 95 5b [2] e1 43 [2] a6 41 [2] e1 50 [2] af 5c [2] a3 56 [2] b4 5d [2] af 13 [2] 92 }

  condition:
    any of them
}