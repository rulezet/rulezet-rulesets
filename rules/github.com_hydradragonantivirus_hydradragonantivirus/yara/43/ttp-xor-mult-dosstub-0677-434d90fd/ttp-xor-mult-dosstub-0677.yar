rule TTP_XOR_MULT_DOSStub_0677 {
  strings:
    $key_0677 = { 52 1f [2] 26 07 [2] 61 05 [2] 26 14 [2] 68 18 [2] 64 12 [2] 73 19 [2] 68 57 [2] 55 }

  condition:
    any of them
}