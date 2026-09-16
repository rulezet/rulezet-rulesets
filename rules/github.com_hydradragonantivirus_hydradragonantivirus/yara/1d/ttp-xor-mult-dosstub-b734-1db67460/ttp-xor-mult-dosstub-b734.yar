rule TTP_XOR_MULT_DOSStub_b734 {
  strings:
    $key_b734 = { e3 5c [2] 97 44 [2] d0 46 [2] 97 57 [2] d9 5b [2] d5 51 [2] c2 5a [2] d9 14 [2] e4 }

  condition:
    any of them
}