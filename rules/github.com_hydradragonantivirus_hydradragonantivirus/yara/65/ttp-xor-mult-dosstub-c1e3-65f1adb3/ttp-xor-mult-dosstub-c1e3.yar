rule TTP_XOR_MULT_DOSStub_c1e3 {
  strings:
    $key_c1e3 = { 95 8b [2] e1 93 [2] a6 91 [2] e1 80 [2] af 8c [2] a3 86 [2] b4 8d [2] af c3 [2] 92 }

  condition:
    any of them
}