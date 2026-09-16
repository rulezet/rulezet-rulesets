rule TTP_XOR_MULT_DOSStub_4d36 {
  strings:
    $key_4d36 = { 19 5e [2] 6d 46 [2] 2a 44 [2] 6d 55 [2] 23 59 [2] 2f 53 [2] 38 58 [2] 23 16 [2] 1e }

  condition:
    any of them
}