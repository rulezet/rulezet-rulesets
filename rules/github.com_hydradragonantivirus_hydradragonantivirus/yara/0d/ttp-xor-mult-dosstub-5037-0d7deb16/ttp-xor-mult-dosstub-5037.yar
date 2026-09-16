rule TTP_XOR_MULT_DOSStub_5037 {
  strings:
    $key_5037 = { 04 5f [2] 70 47 [2] 37 45 [2] 70 54 [2] 3e 58 [2] 32 52 [2] 25 59 [2] 3e 17 [2] 03 }

  condition:
    any of them
}