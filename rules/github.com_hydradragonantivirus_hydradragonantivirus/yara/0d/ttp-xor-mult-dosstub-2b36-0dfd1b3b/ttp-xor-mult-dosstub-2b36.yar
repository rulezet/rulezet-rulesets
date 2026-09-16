rule TTP_XOR_MULT_DOSStub_2b36 {
  strings:
    $key_2b36 = { 7f 5e [2] 0b 46 [2] 4c 44 [2] 0b 55 [2] 45 59 [2] 49 53 [2] 5e 58 [2] 45 16 [2] 78 }

  condition:
    any of them
}