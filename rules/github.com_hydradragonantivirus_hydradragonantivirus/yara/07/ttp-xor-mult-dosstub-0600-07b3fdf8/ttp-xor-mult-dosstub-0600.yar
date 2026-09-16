rule TTP_XOR_MULT_DOSStub_0600 {
  strings:
    $key_0600 = { 52 68 [2] 26 70 [2] 61 72 [2] 26 63 [2] 68 6f [2] 64 65 [2] 73 6e [2] 68 20 [2] 55 }

  condition:
    any of them
}