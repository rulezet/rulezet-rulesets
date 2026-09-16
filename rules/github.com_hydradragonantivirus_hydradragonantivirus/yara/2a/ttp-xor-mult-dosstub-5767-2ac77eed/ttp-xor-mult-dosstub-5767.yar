rule TTP_XOR_MULT_DOSStub_5767 {
  strings:
    $key_5767 = { 03 0f [2] 77 17 [2] 30 15 [2] 77 04 [2] 39 08 [2] 35 02 [2] 22 09 [2] 39 47 [2] 04 }

  condition:
    any of them
}