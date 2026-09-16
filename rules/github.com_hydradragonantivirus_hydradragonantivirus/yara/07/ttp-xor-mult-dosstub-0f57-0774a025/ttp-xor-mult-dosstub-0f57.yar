rule TTP_XOR_MULT_DOSStub_0f57 {
  strings:
    $key_0f57 = { 5b 3f [2] 2f 27 [2] 68 25 [2] 2f 34 [2] 61 38 [2] 6d 32 [2] 7a 39 [2] 61 77 [2] 5c }

  condition:
    any of them
}