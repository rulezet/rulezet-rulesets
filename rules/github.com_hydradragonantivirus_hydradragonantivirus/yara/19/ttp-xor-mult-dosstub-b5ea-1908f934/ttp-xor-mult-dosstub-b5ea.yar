rule TTP_XOR_MULT_DOSStub_b5ea {
  strings:
    $key_b5ea = { e1 82 [2] 95 9a [2] d2 98 [2] 95 89 [2] db 85 [2] d7 8f [2] c0 84 [2] db ca [2] e6 }

  condition:
    any of them
}