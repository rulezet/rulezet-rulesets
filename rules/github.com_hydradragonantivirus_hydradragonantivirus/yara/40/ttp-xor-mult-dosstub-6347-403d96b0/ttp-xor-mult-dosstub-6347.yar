rule TTP_XOR_MULT_DOSStub_6347 {
  strings:
    $key_6347 = { 37 2f [2] 43 37 [2] 04 35 [2] 43 24 [2] 0d 28 [2] 01 22 [2] 16 29 [2] 0d 67 [2] 30 }

  condition:
    any of them
}