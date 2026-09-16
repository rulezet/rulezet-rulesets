rule TTP_XOR_MULT_DOSStub_b57c {
  strings:
    $key_b57c = { e1 14 [2] 95 0c [2] d2 0e [2] 95 1f [2] db 13 [2] d7 19 [2] c0 12 [2] db 5c [2] e6 }

  condition:
    any of them
}