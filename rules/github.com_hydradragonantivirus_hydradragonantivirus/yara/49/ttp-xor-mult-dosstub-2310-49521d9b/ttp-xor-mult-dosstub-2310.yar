rule TTP_XOR_MULT_DOSStub_2310 {
  strings:
    $key_2310 = { 77 78 [2] 03 60 [2] 44 62 [2] 03 73 [2] 4d 7f [2] 41 75 [2] 56 7e [2] 4d 30 [2] 70 }

  condition:
    any of them
}