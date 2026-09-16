rule TTP_XOR_MULT_DOSStub_c82e {
  strings:
    $key_c82e = { 9c 46 [2] e8 5e [2] af 5c [2] e8 4d [2] a6 41 [2] aa 4b [2] bd 40 [2] a6 0e [2] 9b }

  condition:
    any of them
}