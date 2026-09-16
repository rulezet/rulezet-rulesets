rule TTP_XOR_MULT_DOSStub_1271 {
  strings:
    $key_1271 = { 46 19 [2] 32 01 [2] 75 03 [2] 32 12 [2] 7c 1e [2] 70 14 [2] 67 1f [2] 7c 51 [2] 41 }

  condition:
    any of them
}