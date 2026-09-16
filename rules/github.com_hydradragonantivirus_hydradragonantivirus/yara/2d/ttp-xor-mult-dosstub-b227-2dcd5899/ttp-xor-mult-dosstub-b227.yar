rule TTP_XOR_MULT_DOSStub_b227 {
  strings:
    $key_b227 = { e6 4f [2] 92 57 [2] d5 55 [2] 92 44 [2] dc 48 [2] d0 42 [2] c7 49 [2] dc 07 [2] e1 }

  condition:
    any of them
}