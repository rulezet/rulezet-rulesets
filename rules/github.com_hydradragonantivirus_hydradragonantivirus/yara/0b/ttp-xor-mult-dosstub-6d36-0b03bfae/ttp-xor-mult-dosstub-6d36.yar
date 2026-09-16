rule TTP_XOR_MULT_DOSStub_6d36 {
  strings:
    $key_6d36 = { 39 5e [2] 4d 46 [2] 0a 44 [2] 4d 55 [2] 03 59 [2] 0f 53 [2] 18 58 [2] 03 16 [2] 3e }

  condition:
    any of them
}