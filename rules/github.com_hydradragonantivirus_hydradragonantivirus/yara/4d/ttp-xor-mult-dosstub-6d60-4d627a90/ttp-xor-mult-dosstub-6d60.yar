rule TTP_XOR_MULT_DOSStub_6d60 {
  strings:
    $key_6d60 = { 39 08 [2] 4d 10 [2] 0a 12 [2] 4d 03 [2] 03 0f [2] 0f 05 [2] 18 0e [2] 03 40 [2] 3e }

  condition:
    any of them
}