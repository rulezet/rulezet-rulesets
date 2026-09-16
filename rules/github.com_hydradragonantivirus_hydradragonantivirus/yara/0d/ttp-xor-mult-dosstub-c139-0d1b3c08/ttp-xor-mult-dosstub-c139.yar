rule TTP_XOR_MULT_DOSStub_c139 {
  strings:
    $key_c139 = { 95 51 [2] e1 49 [2] a6 4b [2] e1 5a [2] af 56 [2] a3 5c [2] b4 57 [2] af 19 [2] 92 }

  condition:
    any of them
}