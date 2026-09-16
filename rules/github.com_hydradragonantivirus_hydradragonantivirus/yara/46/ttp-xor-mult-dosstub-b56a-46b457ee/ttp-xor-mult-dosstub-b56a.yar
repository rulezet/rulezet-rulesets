rule TTP_XOR_MULT_DOSStub_b56a {
  strings:
    $key_b56a = { e1 02 [2] 95 1a [2] d2 18 [2] 95 09 [2] db 05 [2] d7 0f [2] c0 04 [2] db 4a [2] e6 }

  condition:
    any of them
}