rule TTP_XOR_MULT_DOSStub_e807 {
  strings:
    $key_e807 = { bc 6f [2] c8 77 [2] 8f 75 [2] c8 64 [2] 86 68 [2] 8a 62 [2] 9d 69 [2] 86 27 [2] bb }

  condition:
    any of them
}