rule TTP_XOR_MULT_DOSStub_b24e {
  strings:
    $key_b24e = { e6 26 [2] 92 3e [2] d5 3c [2] 92 2d [2] dc 21 [2] d0 2b [2] c7 20 [2] dc 6e [2] e1 }

  condition:
    any of them
}