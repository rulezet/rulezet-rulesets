rule TTP_XOR_MULT_DOSStub_0666 {
  strings:
    $key_0666 = { 52 0e [2] 26 16 [2] 61 14 [2] 26 05 [2] 68 09 [2] 64 03 [2] 73 08 [2] 68 46 [2] 55 }

  condition:
    any of them
}