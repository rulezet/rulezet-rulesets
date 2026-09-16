rule TTP_XOR_MULT_DOSStub_2271 {
  strings:
    $key_2271 = { 76 19 [2] 02 01 [2] 45 03 [2] 02 12 [2] 4c 1e [2] 40 14 [2] 57 1f [2] 4c 51 [2] 71 }

  condition:
    any of them
}