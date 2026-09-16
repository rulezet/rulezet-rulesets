rule TTP_XOR_MULT_DOSStub_3406 {
  strings:
    $key_3406 = { 60 6e [2] 14 76 [2] 53 74 [2] 14 65 [2] 5a 69 [2] 56 63 [2] 41 68 [2] 5a 26 [2] 67 }

  condition:
    any of them
}