rule TTP_XOR_MULT_DOSStub_b5fc {
  strings:
    $key_b5fc = { e1 94 [2] 95 8c [2] d2 8e [2] 95 9f [2] db 93 [2] d7 99 [2] c0 92 [2] db dc [2] e6 }

  condition:
    any of them
}