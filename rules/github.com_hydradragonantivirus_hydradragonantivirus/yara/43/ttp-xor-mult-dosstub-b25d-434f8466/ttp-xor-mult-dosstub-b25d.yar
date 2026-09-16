rule TTP_XOR_MULT_DOSStub_b25d {
  strings:
    $key_b25d = { e6 35 [2] 92 2d [2] d5 2f [2] 92 3e [2] dc 32 [2] d0 38 [2] c7 33 [2] dc 7d [2] e1 }

  condition:
    any of them
}