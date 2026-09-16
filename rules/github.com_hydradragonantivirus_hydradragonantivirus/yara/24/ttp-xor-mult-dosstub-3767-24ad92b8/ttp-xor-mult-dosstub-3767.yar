rule TTP_XOR_MULT_DOSStub_3767 {
  strings:
    $key_3767 = { 63 0f [2] 17 17 [2] 50 15 [2] 17 04 [2] 59 08 [2] 55 02 [2] 42 09 [2] 59 47 [2] 64 }

  condition:
    any of them
}