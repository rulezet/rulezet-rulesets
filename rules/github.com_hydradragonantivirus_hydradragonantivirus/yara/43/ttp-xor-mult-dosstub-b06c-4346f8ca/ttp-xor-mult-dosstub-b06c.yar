rule TTP_XOR_MULT_DOSStub_b06c {
  strings:
    $key_b06c = { e4 04 [2] 90 1c [2] d7 1e [2] 90 0f [2] de 03 [2] d2 09 [2] c5 02 [2] de 4c [2] e3 }

  condition:
    any of them
}