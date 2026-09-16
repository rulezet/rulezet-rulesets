rule TTP_XOR_MULT_DOSStub_57f7 {
  strings:
    $key_57f7 = { 03 9f [2] 77 87 [2] 30 85 [2] 77 94 [2] 39 98 [2] 35 92 [2] 22 99 [2] 39 d7 [2] 04 }

  condition:
    any of them
}