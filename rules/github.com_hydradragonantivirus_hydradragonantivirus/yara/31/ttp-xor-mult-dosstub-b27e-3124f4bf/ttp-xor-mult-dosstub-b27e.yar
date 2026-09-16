rule TTP_XOR_MULT_DOSStub_b27e {
  strings:
    $key_b27e = { e6 16 [2] 92 0e [2] d5 0c [2] 92 1d [2] dc 11 [2] d0 1b [2] c7 10 [2] dc 5e [2] e1 }

  condition:
    any of them
}