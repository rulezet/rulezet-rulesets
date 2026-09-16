rule TTP_XOR_MULT_DOSStub_71f0 {
  strings:
    $key_71f0 = { 25 98 [2] 51 80 [2] 16 82 [2] 51 93 [2] 1f 9f [2] 13 95 [2] 04 9e [2] 1f d0 [2] 22 }

  condition:
    any of them
}