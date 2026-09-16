rule TTP_XOR_MULT_DOSStub_a771 {
  strings:
    $key_a771 = { f3 19 [2] 87 01 [2] c0 03 [2] 87 12 [2] c9 1e [2] c5 14 [2] d2 1f [2] c9 51 [2] f4 }

  condition:
    any of them
}