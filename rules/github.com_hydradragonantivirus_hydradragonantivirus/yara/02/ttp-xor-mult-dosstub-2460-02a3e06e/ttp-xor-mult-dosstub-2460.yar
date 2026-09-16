rule TTP_XOR_MULT_DOSStub_2460 {
  strings:
    $key_2460 = { 70 08 [2] 04 10 [2] 43 12 [2] 04 03 [2] 4a 0f [2] 46 05 [2] 51 0e [2] 4a 40 [2] 77 }

  condition:
    any of them
}