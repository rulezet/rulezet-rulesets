rule TTP_XOR_MULT_DOSStub_c87e {
  strings:
    $key_c87e = { 9c 16 [2] e8 0e [2] af 0c [2] e8 1d [2] a6 11 [2] aa 1b [2] bd 10 [2] a6 5e [2] 9b }

  condition:
    any of them
}