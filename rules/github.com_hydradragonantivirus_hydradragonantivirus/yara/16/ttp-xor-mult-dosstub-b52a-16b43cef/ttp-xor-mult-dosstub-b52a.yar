rule TTP_XOR_MULT_DOSStub_b52a {
  strings:
    $key_b52a = { e1 42 [2] 95 5a [2] d2 58 [2] 95 49 [2] db 45 [2] d7 4f [2] c0 44 [2] db 0a [2] e6 }

  condition:
    any of them
}