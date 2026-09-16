rule TTP_XOR_MULT_DOSStub_b234 {
  strings:
    $key_b234 = { e6 5c [2] 92 44 [2] d5 46 [2] 92 57 [2] dc 5b [2] d0 51 [2] c7 5a [2] dc 14 [2] e1 }

  condition:
    any of them
}