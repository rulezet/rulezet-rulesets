rule TTP_XOR_MULT_DOSStub_b7e8 {
  strings:
    $key_b7e8 = { e3 80 [2] 97 98 [2] d0 9a [2] 97 8b [2] d9 87 [2] d5 8d [2] c2 86 [2] d9 c8 [2] e4 }

  condition:
    any of them
}