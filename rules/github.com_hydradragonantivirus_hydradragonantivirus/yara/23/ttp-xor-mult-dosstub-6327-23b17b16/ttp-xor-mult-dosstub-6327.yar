rule TTP_XOR_MULT_DOSStub_6327 {
  strings:
    $key_6327 = { 37 4f [2] 43 57 [2] 04 55 [2] 43 44 [2] 0d 48 [2] 01 42 [2] 16 49 [2] 0d 07 [2] 30 }

  condition:
    any of them
}