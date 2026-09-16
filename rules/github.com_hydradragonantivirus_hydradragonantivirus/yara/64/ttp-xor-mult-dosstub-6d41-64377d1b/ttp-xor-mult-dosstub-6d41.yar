rule TTP_XOR_MULT_DOSStub_6d41 {
  strings:
    $key_6d41 = { 39 29 [2] 4d 31 [2] 0a 33 [2] 4d 22 [2] 03 2e [2] 0f 24 [2] 18 2f [2] 03 61 [2] 3e }

  condition:
    any of them
}