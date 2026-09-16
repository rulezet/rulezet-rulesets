rule TTP_XOR_MULT_DOSStub_b22d {
  strings:
    $key_b22d = { e6 45 [2] 92 5d [2] d5 5f [2] 92 4e [2] dc 42 [2] d0 48 [2] c7 43 [2] dc 0d [2] e1 }

  condition:
    any of them
}