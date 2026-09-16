rule TTP_XOR_MULT_DOSStub_b51e {
  strings:
    $key_b51e = { e1 76 [2] 95 6e [2] d2 6c [2] 95 7d [2] db 71 [2] d7 7b [2] c0 70 [2] db 3e [2] e6 }

  condition:
    any of them
}