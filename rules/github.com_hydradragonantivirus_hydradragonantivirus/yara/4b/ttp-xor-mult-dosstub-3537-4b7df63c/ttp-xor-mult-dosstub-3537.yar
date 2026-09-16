rule TTP_XOR_MULT_DOSStub_3537 {
  strings:
    $key_3537 = { 61 5f [2] 15 47 [2] 52 45 [2] 15 54 [2] 5b 58 [2] 57 52 [2] 40 59 [2] 5b 17 [2] 66 }

  condition:
    any of them
}