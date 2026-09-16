rule TTP_XOR_MULT_DOSStub_b204 {
  strings:
    $key_b204 = { e6 6c [2] 92 74 [2] d5 76 [2] 92 67 [2] dc 6b [2] d0 61 [2] c7 6a [2] dc 24 [2] e1 }

  condition:
    any of them
}