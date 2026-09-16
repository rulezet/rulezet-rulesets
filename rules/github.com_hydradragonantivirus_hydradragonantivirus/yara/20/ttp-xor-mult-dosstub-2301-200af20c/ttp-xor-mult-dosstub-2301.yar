rule TTP_XOR_MULT_DOSStub_2301 {
  strings:
    $key_2301 = { 77 69 [2] 03 71 [2] 44 73 [2] 03 62 [2] 4d 6e [2] 41 64 [2] 56 6f [2] 4d 21 [2] 70 }

  condition:
    any of them
}