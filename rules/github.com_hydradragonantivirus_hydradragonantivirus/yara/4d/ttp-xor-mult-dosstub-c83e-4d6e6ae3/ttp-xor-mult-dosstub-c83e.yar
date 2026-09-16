rule TTP_XOR_MULT_DOSStub_c83e {
  strings:
    $key_c83e = { 9c 56 [2] e8 4e [2] af 4c [2] e8 5d [2] a6 51 [2] aa 5b [2] bd 50 [2] a6 1e [2] 9b }

  condition:
    any of them
}