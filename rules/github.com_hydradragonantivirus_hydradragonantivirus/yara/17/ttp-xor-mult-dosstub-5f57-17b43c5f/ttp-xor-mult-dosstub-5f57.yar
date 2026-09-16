rule TTP_XOR_MULT_DOSStub_5f57 {
  strings:
    $key_5f57 = { 0b 3f [2] 7f 27 [2] 38 25 [2] 7f 34 [2] 31 38 [2] 3d 32 [2] 2a 39 [2] 31 77 [2] 0c }

  condition:
    any of them
}