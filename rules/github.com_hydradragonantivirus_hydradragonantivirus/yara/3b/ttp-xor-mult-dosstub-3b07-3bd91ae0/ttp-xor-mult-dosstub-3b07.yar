rule TTP_XOR_MULT_DOSStub_3b07 {
  strings:
    $key_3b07 = { 6f 6f [2] 1b 77 [2] 5c 75 [2] 1b 64 [2] 55 68 [2] 59 62 [2] 4e 69 [2] 55 27 [2] 68 }

  condition:
    any of them
}