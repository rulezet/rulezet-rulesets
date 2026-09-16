rule TTP_XOR_MULT_DOSStub_7d36 {
  strings:
    $key_7d36 = { 29 5e [2] 5d 46 [2] 1a 44 [2] 5d 55 [2] 13 59 [2] 1f 53 [2] 08 58 [2] 13 16 [2] 2e }

  condition:
    any of them
}