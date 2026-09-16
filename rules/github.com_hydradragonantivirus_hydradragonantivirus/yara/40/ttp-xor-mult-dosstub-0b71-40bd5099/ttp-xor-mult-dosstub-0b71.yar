rule TTP_XOR_MULT_DOSStub_0b71 {
  strings:
    $key_0b71 = { 5f 19 [2] 2b 01 [2] 6c 03 [2] 2b 12 [2] 65 1e [2] 69 14 [2] 7e 1f [2] 65 51 [2] 58 }

  condition:
    any of them
}