rule TTP_XOR_MULT_DOSStub_5707 {
  strings:
    $key_5707 = { 03 6f [2] 77 77 [2] 30 75 [2] 77 64 [2] 39 68 [2] 35 62 [2] 22 69 [2] 39 27 [2] 04 }

  condition:
    any of them
}