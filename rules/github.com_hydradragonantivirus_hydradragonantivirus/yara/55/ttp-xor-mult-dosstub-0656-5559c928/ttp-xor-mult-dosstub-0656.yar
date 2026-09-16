rule TTP_XOR_MULT_DOSStub_0656 {
  strings:
    $key_0656 = { 52 3e [2] 26 26 [2] 61 24 [2] 26 35 [2] 68 39 [2] 64 33 [2] 73 38 [2] 68 76 [2] 55 }

  condition:
    any of them
}