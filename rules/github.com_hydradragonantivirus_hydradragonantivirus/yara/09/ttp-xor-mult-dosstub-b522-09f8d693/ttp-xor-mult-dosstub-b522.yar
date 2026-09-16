rule TTP_XOR_MULT_DOSStub_b522 {
  strings:
    $key_b522 = { e1 4a [2] 95 52 [2] d2 50 [2] 95 41 [2] db 4d [2] d7 47 [2] c0 4c [2] db 02 [2] e6 }

  condition:
    any of them
}