rule TTP_XOR_MULT_DOSStub_6f07 {
  strings:
    $key_6f07 = { 3b 6f [2] 4f 77 [2] 08 75 [2] 4f 64 [2] 01 68 [2] 0d 62 [2] 1a 69 [2] 01 27 [2] 3c }

  condition:
    any of them
}