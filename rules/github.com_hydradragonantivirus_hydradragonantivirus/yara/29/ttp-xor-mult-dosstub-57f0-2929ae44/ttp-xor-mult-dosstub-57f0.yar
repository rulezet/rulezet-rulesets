rule TTP_XOR_MULT_DOSStub_57f0 {
  strings:
    $key_57f0 = { 03 98 [2] 77 80 [2] 30 82 [2] 77 93 [2] 39 9f [2] 35 95 [2] 22 9e [2] 39 d0 [2] 04 }

  condition:
    any of them
}