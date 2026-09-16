rule TTP_XOR_MULT_DOSStub_1f07 {
  strings:
    $key_1f07 = { 4b 6f [2] 3f 77 [2] 78 75 [2] 3f 64 [2] 71 68 [2] 7d 62 [2] 6a 69 [2] 71 27 [2] 4c }

  condition:
    any of them
}