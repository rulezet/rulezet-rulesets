rule TTP_XOR_MULT_DOSStub_c1f3 {
  strings:
    $key_c1f3 = { 95 9b [2] e1 83 [2] a6 81 [2] e1 90 [2] af 9c [2] a3 96 [2] b4 9d [2] af d3 [2] 92 }

  condition:
    any of them
}