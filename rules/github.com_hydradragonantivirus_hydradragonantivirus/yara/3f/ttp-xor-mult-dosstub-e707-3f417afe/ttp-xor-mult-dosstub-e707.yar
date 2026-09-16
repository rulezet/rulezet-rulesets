rule TTP_XOR_MULT_DOSStub_e707 {
  strings:
    $key_e707 = { b3 6f [2] c7 77 [2] 80 75 [2] c7 64 [2] 89 68 [2] 85 62 [2] 92 69 [2] 89 27 [2] b4 }

  condition:
    any of them
}