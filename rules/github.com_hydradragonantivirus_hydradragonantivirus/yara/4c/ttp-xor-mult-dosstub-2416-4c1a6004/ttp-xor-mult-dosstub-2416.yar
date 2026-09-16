rule TTP_XOR_MULT_DOSStub_2416 {
  strings:
    $key_2416 = { 70 7e [2] 04 66 [2] 43 64 [2] 04 75 [2] 4a 79 [2] 46 73 [2] 51 78 [2] 4a 36 [2] 77 }

  condition:
    any of them
}