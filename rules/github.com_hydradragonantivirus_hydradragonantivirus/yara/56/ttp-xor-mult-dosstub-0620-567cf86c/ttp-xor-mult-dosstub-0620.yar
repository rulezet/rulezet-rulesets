rule TTP_XOR_MULT_DOSStub_0620 {
  strings:
    $key_0620 = { 52 48 [2] 26 50 [2] 61 52 [2] 26 43 [2] 68 4f [2] 64 45 [2] 73 4e [2] 68 00 [2] 55 }

  condition:
    any of them
}