rule TTP_XOR_MULT_DOSStub_0071 {
  strings:
    $key_0071 = { 54 19 [2] 20 01 [2] 67 03 [2] 20 12 [2] 6e 1e [2] 62 14 [2] 75 1f [2] 6e 51 [2] 53 }

  condition:
    any of them
}