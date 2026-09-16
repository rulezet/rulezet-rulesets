rule TTP_XOR_MULT_DOSStub_2f66 {
  strings:
    $key_2f66 = { 7b 0e [2] 0f 16 [2] 48 14 [2] 0f 05 [2] 41 09 [2] 4d 03 [2] 5a 08 [2] 41 46 [2] 7c }

  condition:
    any of them
}