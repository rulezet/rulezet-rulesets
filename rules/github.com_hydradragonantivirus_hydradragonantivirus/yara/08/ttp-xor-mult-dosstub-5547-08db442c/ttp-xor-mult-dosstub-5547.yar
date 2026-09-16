rule TTP_XOR_MULT_DOSStub_5547 {
  strings:
    $key_5547 = { 01 2f [2] 75 37 [2] 32 35 [2] 75 24 [2] 3b 28 [2] 37 22 [2] 20 29 [2] 3b 67 [2] 06 }

  condition:
    any of them
}