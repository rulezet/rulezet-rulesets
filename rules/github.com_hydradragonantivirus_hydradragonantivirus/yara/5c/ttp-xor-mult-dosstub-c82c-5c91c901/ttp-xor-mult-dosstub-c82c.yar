rule TTP_XOR_MULT_DOSStub_c82c {
  strings:
    $key_c82c = { 9c 44 [2] e8 5c [2] af 5e [2] e8 4f [2] a6 43 [2] aa 49 [2] bd 42 [2] a6 0c [2] 9b }

  condition:
    any of them
}