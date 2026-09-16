rule TTP_XOR_MULT_DOSStub_5760 {
  strings:
    $key_5760 = { 03 08 [2] 77 10 [2] 30 12 [2] 77 03 [2] 39 0f [2] 35 05 [2] 22 0e [2] 39 40 [2] 04 }

  condition:
    any of them
}