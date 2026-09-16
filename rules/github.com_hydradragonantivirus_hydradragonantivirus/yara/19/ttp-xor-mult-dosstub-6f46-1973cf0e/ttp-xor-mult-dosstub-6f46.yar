rule TTP_XOR_MULT_DOSStub_6f46 {
  strings:
    $key_6f46 = { 3b 2e [2] 4f 36 [2] 08 34 [2] 4f 25 [2] 01 29 [2] 0d 23 [2] 1a 28 [2] 01 66 [2] 3c }

  condition:
    any of them
}