rule TTP_XOR_MULT_DOSStub_b5fd {
  strings:
    $key_b5fd = { e1 95 [2] 95 8d [2] d2 8f [2] 95 9e [2] db 92 [2] d7 98 [2] c0 93 [2] db dd [2] e6 }

  condition:
    any of them
}