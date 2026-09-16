rule TTP_XOR_MULT_DOSStub_b7eb {
  strings:
    $key_b7eb = { e3 83 [2] 97 9b [2] d0 99 [2] 97 88 [2] d9 84 [2] d5 8e [2] c2 85 [2] d9 cb [2] e4 }

  condition:
    any of them
}