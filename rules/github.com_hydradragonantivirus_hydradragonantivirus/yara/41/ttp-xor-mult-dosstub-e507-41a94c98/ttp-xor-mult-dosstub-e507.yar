rule TTP_XOR_MULT_DOSStub_e507 {
  strings:
    $key_e507 = { b1 6f [2] c5 77 [2] 82 75 [2] c5 64 [2] 8b 68 [2] 87 62 [2] 90 69 [2] 8b 27 [2] b6 }

  condition:
    any of them
}