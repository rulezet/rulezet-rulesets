rule TTP_XOR_MULT_DOSStub_c1f2 {
  strings:
    $key_c1f2 = { 95 9a [2] e1 82 [2] a6 80 [2] e1 91 [2] af 9d [2] a3 97 [2] b4 9c [2] af d2 [2] 92 }

  condition:
    any of them
}