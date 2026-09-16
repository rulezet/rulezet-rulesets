rule TTP_XOR_MULT_DOSStub_b27d {
  strings:
    $key_b27d = { e6 15 [2] 92 0d [2] d5 0f [2] 92 1e [2] dc 12 [2] d0 18 [2] c7 13 [2] dc 5d [2] e1 }

  condition:
    any of them
}