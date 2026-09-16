rule TTP_XOR_MULT_DOSStub_b5f2 {
  strings:
    $key_b5f2 = { e1 9a [2] 95 82 [2] d2 80 [2] 95 91 [2] db 9d [2] d7 97 [2] c0 9c [2] db d2 [2] e6 }

  condition:
    any of them
}