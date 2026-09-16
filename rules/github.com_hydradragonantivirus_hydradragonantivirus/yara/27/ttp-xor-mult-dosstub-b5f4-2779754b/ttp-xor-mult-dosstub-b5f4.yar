rule TTP_XOR_MULT_DOSStub_b5f4 {
  strings:
    $key_b5f4 = { e1 9c [2] 95 84 [2] d2 86 [2] 95 97 [2] db 9b [2] d7 91 [2] c0 9a [2] db d4 [2] e6 }

  condition:
    any of them
}