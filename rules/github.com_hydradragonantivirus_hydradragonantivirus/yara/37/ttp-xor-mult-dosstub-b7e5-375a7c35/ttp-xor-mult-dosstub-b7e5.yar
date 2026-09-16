rule TTP_XOR_MULT_DOSStub_b7e5 {
  strings:
    $key_b7e5 = { e3 8d [2] 97 95 [2] d0 97 [2] 97 86 [2] d9 8a [2] d5 80 [2] c2 8b [2] d9 c5 [2] e4 }

  condition:
    any of them
}