rule TTP_XOR_MULT_DOSStub_5766 {
  strings:
    $key_5766 = { 03 0e [2] 77 16 [2] 30 14 [2] 77 05 [2] 39 09 [2] 35 03 [2] 22 08 [2] 39 46 [2] 04 }

  condition:
    any of them
}