rule TTP_XOR_MULT_DOSStub_b76c {
  strings:
    $key_b76c = { e3 04 [2] 97 1c [2] d0 1e [2] 97 0f [2] d9 03 [2] d5 09 [2] c2 02 [2] d9 4c [2] e4 }

  condition:
    any of them
}