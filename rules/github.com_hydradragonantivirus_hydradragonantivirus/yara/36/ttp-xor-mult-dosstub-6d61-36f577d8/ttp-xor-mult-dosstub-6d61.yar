rule TTP_XOR_MULT_DOSStub_6d61 {
  strings:
    $key_6d61 = { 39 09 [2] 4d 11 [2] 0a 13 [2] 4d 02 [2] 03 0e [2] 0f 04 [2] 18 0f [2] 03 41 [2] 3e }

  condition:
    any of them
}