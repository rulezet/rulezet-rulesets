rule TTP_XOR_MULT_DOSStub_b36c {
  strings:
    $key_b36c = { e7 04 [2] 93 1c [2] d4 1e [2] 93 0f [2] dd 03 [2] d1 09 [2] c6 02 [2] dd 4c [2] e0 }

  condition:
    any of them
}