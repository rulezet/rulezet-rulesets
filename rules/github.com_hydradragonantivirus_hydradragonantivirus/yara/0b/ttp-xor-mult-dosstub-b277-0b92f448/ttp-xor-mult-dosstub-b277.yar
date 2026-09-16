rule TTP_XOR_MULT_DOSStub_b277 {
  strings:
    $key_b277 = { e6 1f [2] 92 07 [2] d5 05 [2] 92 14 [2] dc 18 [2] d0 12 [2] c7 19 [2] dc 57 [2] e1 }

  condition:
    any of them
}