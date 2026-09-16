rule TTP_XOR_MULT_DOSStub_6706 {
  strings:
    $key_6706 = { 33 6e [2] 47 76 [2] 00 74 [2] 47 65 [2] 09 69 [2] 05 63 [2] 12 68 [2] 09 26 [2] 34 }

  condition:
    any of them
}