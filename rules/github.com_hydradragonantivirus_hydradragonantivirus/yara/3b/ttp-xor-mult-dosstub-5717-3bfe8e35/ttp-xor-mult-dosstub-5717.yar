rule TTP_XOR_MULT_DOSStub_5717 {
  strings:
    $key_5717 = { 03 7f [2] 77 67 [2] 30 65 [2] 77 74 [2] 39 78 [2] 35 72 [2] 22 79 [2] 39 37 [2] 04 }

  condition:
    any of them
}