rule TTP_XOR_MULT_DOSStub_1f57 {
  strings:
    $key_1f57 = { 4b 3f [2] 3f 27 [2] 78 25 [2] 3f 34 [2] 71 38 [2] 7d 32 [2] 6a 39 [2] 71 77 [2] 4c }

  condition:
    any of them
}