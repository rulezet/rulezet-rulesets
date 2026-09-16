rule TTP_XOR_MULT_DOSStub_6d77 {
  strings:
    $key_6d77 = { 39 1f [2] 4d 07 [2] 0a 05 [2] 4d 14 [2] 03 18 [2] 0f 12 [2] 18 19 [2] 03 57 [2] 3e }

  condition:
    any of them
}