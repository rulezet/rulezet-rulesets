rule TTP_XOR_MULT_DOSStub_5671 {
  strings:
    $key_5671 = { 02 19 [2] 76 01 [2] 31 03 [2] 76 12 [2] 38 1e [2] 34 14 [2] 23 1f [2] 38 51 [2] 05 }

  condition:
    any of them
}