rule TTP_XOR_MULT_DOSStub_b215 {
  strings:
    $key_b215 = { e6 7d [2] 92 65 [2] d5 67 [2] 92 76 [2] dc 7a [2] d0 70 [2] c7 7b [2] dc 35 [2] e1 }

  condition:
    any of them
}