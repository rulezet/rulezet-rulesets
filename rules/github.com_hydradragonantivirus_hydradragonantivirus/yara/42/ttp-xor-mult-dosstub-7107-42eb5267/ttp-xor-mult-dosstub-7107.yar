rule TTP_XOR_MULT_DOSStub_7107 {
  strings:
    $key_7107 = { 25 6f [2] 51 77 [2] 16 75 [2] 51 64 [2] 1f 68 [2] 13 62 [2] 04 69 [2] 1f 27 [2] 22 }

  condition:
    any of them
}