rule TTP_XOR_MULT_DOSStub_b7f4 {
  strings:
    $key_b7f4 = { e3 9c [2] 97 84 [2] d0 86 [2] 97 97 [2] d9 9b [2] d5 91 [2] c2 9a [2] d9 d4 [2] e4 }

  condition:
    any of them
}