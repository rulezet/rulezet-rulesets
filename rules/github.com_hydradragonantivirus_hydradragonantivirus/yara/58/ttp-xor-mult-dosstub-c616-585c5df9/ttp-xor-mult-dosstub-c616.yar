rule TTP_XOR_MULT_DOSStub_c616 {
  strings:
    $key_c616 = { 92 7e [2] e6 66 [2] a1 64 [2] e6 75 [2] a8 79 [2] a4 73 [2] b3 78 [2] a8 36 [2] 95 }

  condition:
    any of them
}