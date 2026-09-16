rule TTP_XOR_MULT_DOSStub_c82d {
  strings:
    $key_c82d = { 9c 45 [2] e8 5d [2] af 5f [2] e8 4e [2] a6 42 [2] aa 48 [2] bd 43 [2] a6 0d [2] 9b }

  condition:
    any of them
}