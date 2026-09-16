rule TTP_XOR_MULT_DOSStub_b32d {
  strings:
    $key_b32d = { e7 45 [2] 93 5d [2] d4 5f [2] 93 4e [2] dd 42 [2] d1 48 [2] c6 43 [2] dd 0d [2] e0 }

  condition:
    any of them
}