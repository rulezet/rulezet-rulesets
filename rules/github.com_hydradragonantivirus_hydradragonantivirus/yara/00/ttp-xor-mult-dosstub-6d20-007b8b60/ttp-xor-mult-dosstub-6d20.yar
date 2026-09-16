rule TTP_XOR_MULT_DOSStub_6d20 {
  strings:
    $key_6d20 = { 39 48 [2] 4d 50 [2] 0a 52 [2] 4d 43 [2] 03 4f [2] 0f 45 [2] 18 4e [2] 03 00 [2] 3e }

  condition:
    any of them
}