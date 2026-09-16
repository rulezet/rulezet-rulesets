rule TTP_XOR_MULT_DOSStub_b25e {
  strings:
    $key_b25e = { e6 36 [2] 92 2e [2] d5 2c [2] 92 3d [2] dc 31 [2] d0 3b [2] c7 30 [2] dc 7e [2] e1 }

  condition:
    any of them
}