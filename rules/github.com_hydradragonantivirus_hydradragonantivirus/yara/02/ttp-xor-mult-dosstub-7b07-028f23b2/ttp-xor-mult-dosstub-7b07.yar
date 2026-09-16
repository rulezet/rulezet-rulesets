rule TTP_XOR_MULT_DOSStub_7b07 {
  strings:
    $key_7b07 = { 2f 6f [2] 5b 77 [2] 1c 75 [2] 5b 64 [2] 15 68 [2] 19 62 [2] 0e 69 [2] 15 27 [2] 28 }

  condition:
    any of them
}