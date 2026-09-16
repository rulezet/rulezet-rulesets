rule TTP_XOR_MULT_DOSStub_24f0 {
  strings:
    $key_24f0 = { 70 98 [2] 04 80 [2] 43 82 [2] 04 93 [2] 4a 9f [2] 46 95 [2] 51 9e [2] 4a d0 [2] 77 }

  condition:
    any of them
}