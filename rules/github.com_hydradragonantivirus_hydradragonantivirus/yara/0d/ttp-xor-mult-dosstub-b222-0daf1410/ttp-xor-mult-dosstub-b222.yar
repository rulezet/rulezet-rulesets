rule TTP_XOR_MULT_DOSStub_b222 {
  strings:
    $key_b222 = { e6 4a [2] 92 52 [2] d5 50 [2] 92 41 [2] dc 4d [2] d0 47 [2] c7 4c [2] dc 02 [2] e1 }

  condition:
    any of them
}