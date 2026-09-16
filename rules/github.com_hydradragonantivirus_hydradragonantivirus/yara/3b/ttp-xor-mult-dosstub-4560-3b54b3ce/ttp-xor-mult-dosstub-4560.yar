rule TTP_XOR_MULT_DOSStub_4560 {
  strings:
    $key_4560 = { 11 08 [2] 65 10 [2] 22 12 [2] 65 03 [2] 2b 0f [2] 27 05 [2] 30 0e [2] 2b 40 [2] 16 }

  condition:
    any of them
}