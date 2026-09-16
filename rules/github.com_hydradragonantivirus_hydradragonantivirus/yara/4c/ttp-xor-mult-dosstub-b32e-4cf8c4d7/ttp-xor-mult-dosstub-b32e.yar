rule TTP_XOR_MULT_DOSStub_b32e {
  strings:
    $key_b32e = { e7 46 [2] 93 5e [2] d4 5c [2] 93 4d [2] dd 41 [2] d1 4b [2] c6 40 [2] dd 0e [2] e0 }

  condition:
    any of them
}