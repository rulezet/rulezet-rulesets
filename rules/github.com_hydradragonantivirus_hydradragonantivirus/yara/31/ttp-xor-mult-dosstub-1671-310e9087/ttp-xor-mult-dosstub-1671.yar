rule TTP_XOR_MULT_DOSStub_1671 {
  strings:
    $key_1671 = { 42 19 [2] 36 01 [2] 71 03 [2] 36 12 [2] 78 1e [2] 74 14 [2] 63 1f [2] 78 51 [2] 45 }

  condition:
    any of them
}