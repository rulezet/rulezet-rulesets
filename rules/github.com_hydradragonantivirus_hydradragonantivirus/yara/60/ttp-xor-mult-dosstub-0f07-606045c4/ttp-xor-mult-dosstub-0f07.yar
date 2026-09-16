rule TTP_XOR_MULT_DOSStub_0f07 {
  strings:
    $key_0f07 = { 5b 6f [2] 2f 77 [2] 68 75 [2] 2f 64 [2] 61 68 [2] 6d 62 [2] 7a 69 [2] 61 27 [2] 5c }

  condition:
    any of them
}