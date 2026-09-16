rule TTP_XOR_MULT_DOSStub_b52d {
  strings:
    $key_b52d = { e1 45 [2] 95 5d [2] d2 5f [2] 95 4e [2] db 42 [2] d7 48 [2] c0 43 [2] db 0d [2] e6 }

  condition:
    any of them
}