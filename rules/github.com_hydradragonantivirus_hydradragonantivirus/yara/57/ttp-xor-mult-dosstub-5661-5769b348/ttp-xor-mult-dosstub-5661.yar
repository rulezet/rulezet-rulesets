rule TTP_XOR_MULT_DOSStub_5661 {
  strings:
    $key_5661 = { 02 09 [2] 76 11 [2] 31 13 [2] 76 02 [2] 38 0e [2] 34 04 [2] 23 0f [2] 38 41 [2] 05 }

  condition:
    any of them
}