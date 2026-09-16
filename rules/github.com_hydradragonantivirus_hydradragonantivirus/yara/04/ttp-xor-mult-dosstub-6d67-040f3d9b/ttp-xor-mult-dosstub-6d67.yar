rule TTP_XOR_MULT_DOSStub_6d67 {
  strings:
    $key_6d67 = { 39 0f [2] 4d 17 [2] 0a 15 [2] 4d 04 [2] 03 08 [2] 0f 02 [2] 18 09 [2] 03 47 [2] 3e }

  condition:
    any of them
}