rule TTP_XOR_MULT_DOSStub_2707 {
  strings:
    $key_2707 = { 73 6f [2] 07 77 [2] 40 75 [2] 07 64 [2] 49 68 [2] 45 62 [2] 52 69 [2] 49 27 [2] 74 }

  condition:
    any of them
}