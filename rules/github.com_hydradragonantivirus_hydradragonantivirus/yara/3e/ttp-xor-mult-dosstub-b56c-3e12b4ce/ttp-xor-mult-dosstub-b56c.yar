rule TTP_XOR_MULT_DOSStub_b56c {
  strings:
    $key_b56c = { e1 04 [2] 95 1c [2] d2 1e [2] 95 0f [2] db 03 [2] d7 09 [2] c0 02 [2] db 4c [2] e6 }

  condition:
    any of them
}