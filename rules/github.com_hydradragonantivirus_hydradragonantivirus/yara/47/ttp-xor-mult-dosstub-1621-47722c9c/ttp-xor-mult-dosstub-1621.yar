rule TTP_XOR_MULT_DOSStub_1621 {
  strings:
    $key_1621 = { 42 49 [2] 36 51 [2] 71 53 [2] 36 42 [2] 78 4e [2] 74 44 [2] 63 4f [2] 78 01 [2] 45 }

  condition:
    any of them
}