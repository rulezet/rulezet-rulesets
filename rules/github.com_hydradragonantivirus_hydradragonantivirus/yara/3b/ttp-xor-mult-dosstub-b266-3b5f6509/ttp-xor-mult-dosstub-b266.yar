rule TTP_XOR_MULT_DOSStub_b266 {
  strings:
    $key_b266 = { e6 0e [2] 92 16 [2] d5 14 [2] 92 05 [2] dc 09 [2] d0 03 [2] c7 08 [2] dc 46 [2] e1 }

  condition:
    any of them
}