rule TTP_XOR_MULT_DOSStub_2b07 {
  strings:
    $key_2b07 = { 7f 6f [2] 0b 77 [2] 4c 75 [2] 0b 64 [2] 45 68 [2] 49 62 [2] 5e 69 [2] 45 27 [2] 78 }

  condition:
    any of them
}