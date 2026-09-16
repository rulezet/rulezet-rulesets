rule TTP_XOR_MULT_DOSStub_0137 {
  strings:
    $key_0137 = { 55 5f [2] 21 47 [2] 66 45 [2] 21 54 [2] 6f 58 [2] 63 52 [2] 74 59 [2] 6f 17 [2] 52 }

  condition:
    any of them
}