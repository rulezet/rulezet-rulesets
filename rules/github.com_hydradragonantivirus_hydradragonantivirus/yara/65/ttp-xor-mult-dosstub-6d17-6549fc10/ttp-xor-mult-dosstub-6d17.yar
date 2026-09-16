rule TTP_XOR_MULT_DOSStub_6d17 {
  strings:
    $key_6d17 = { 39 7f [2] 4d 67 [2] 0a 65 [2] 4d 74 [2] 03 78 [2] 0f 72 [2] 18 79 [2] 03 37 [2] 3e }

  condition:
    any of them
}