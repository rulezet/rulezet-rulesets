rule TTP_XOR_MULT_DOSStub_b50c {
  strings:
    $key_b50c = { e1 64 [2] 95 7c [2] d2 7e [2] 95 6f [2] db 63 [2] d7 69 [2] c0 62 [2] db 2c [2] e6 }

  condition:
    any of them
}