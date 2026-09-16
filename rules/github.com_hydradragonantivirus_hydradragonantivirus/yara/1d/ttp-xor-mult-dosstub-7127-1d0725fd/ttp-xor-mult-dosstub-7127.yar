rule TTP_XOR_MULT_DOSStub_7127 {
  strings:
    $key_7127 = { 25 4f [2] 51 57 [2] 16 55 [2] 51 44 [2] 1f 48 [2] 13 42 [2] 04 49 [2] 1f 07 [2] 22 }

  condition:
    any of them
}