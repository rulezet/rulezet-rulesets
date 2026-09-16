rule TTP_XOR_MULT_DOSStub_b56b {
  strings:
    $key_b56b = { e1 03 [2] 95 1b [2] d2 19 [2] 95 08 [2] db 04 [2] d7 0e [2] c0 05 [2] db 4b [2] e6 }

  condition:
    any of them
}