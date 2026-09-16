rule TTP_XOR_MULT_DOSStub_b56e {
  strings:
    $key_b56e = { e1 06 [2] 95 1e [2] d2 1c [2] 95 0d [2] db 01 [2] d7 0b [2] c0 00 [2] db 4e [2] e6 }

  condition:
    any of them
}