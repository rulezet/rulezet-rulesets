rule TTP_XOR_MULT_DOSStub_6d00 {
  strings:
    $key_6d00 = { 39 68 [2] 4d 70 [2] 0a 72 [2] 4d 63 [2] 03 6f [2] 0f 65 [2] 18 6e [2] 03 20 [2] 3e }

  condition:
    any of them
}