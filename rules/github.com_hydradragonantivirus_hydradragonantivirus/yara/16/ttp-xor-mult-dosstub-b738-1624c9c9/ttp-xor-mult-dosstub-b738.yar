rule TTP_XOR_MULT_DOSStub_b738 {
  strings:
    $key_b738 = { e3 50 [2] 97 48 [2] d0 4a [2] 97 5b [2] d9 57 [2] d5 5d [2] c2 56 [2] d9 18 [2] e4 }

  condition:
    any of them
}