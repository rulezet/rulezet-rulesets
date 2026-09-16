rule TTP_XOR_MULT_DOSStub_2420 {
  strings:
    $key_2420 = { 70 48 [2] 04 50 [2] 43 52 [2] 04 43 [2] 4a 4f [2] 46 45 [2] 51 4e [2] 4a 00 [2] 77 }

  condition:
    any of them
}