rule TTP_XOR_MULT_DOSStub_b53b {
  strings:
    $key_b53b = { e1 53 [2] 95 4b [2] d2 49 [2] 95 58 [2] db 54 [2] d7 5e [2] c0 55 [2] db 1b [2] e6 }

  condition:
    any of them
}