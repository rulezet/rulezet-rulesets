rule TTP_XOR_MULT_DOSStub_0647 {
  strings:
    $key_0647 = { 52 2f [2] 26 37 [2] 61 35 [2] 26 24 [2] 68 28 [2] 64 22 [2] 73 29 [2] 68 67 [2] 55 }

  condition:
    any of them
}