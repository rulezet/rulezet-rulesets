rule TTP_XOR_MULT_DOSStub_6d06 {
  strings:
    $key_6d06 = { 39 6e [2] 4d 76 [2] 0a 74 [2] 4d 65 [2] 03 69 [2] 0f 63 [2] 18 68 [2] 03 26 [2] 3e }

  condition:
    any of them
}