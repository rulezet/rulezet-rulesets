rule TTP_XOR_MULT_DOSStub_b233 {
  strings:
    $key_b233 = { e6 5b [2] 92 43 [2] d5 41 [2] 92 50 [2] dc 5c [2] d0 56 [2] c7 5d [2] dc 13 [2] e1 }

  condition:
    any of them
}