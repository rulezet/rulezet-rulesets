rule TTP_XOR_MULT_DOSStub_b52e {
  strings:
    $key_b52e = { e1 46 [2] 95 5e [2] d2 5c [2] 95 4d [2] db 41 [2] d7 4b [2] c0 40 [2] db 0e [2] e6 }

  condition:
    any of them
}