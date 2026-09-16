rule TTP_XOR_MULT_DOSStub_0437 {
  strings:
    $key_0437 = { 50 5f [2] 24 47 [2] 63 45 [2] 24 54 [2] 6a 58 [2] 66 52 [2] 71 59 [2] 6a 17 [2] 57 }

  condition:
    any of them
}