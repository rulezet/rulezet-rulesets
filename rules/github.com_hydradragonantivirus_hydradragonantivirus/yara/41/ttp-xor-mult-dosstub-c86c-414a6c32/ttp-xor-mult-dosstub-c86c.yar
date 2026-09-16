rule TTP_XOR_MULT_DOSStub_c86c {
  strings:
    $key_c86c = { 9c 04 [2] e8 1c [2] af 1e [2] e8 0f [2] a6 03 [2] aa 09 [2] bd 02 [2] a6 4c [2] 9b }

  condition:
    any of them
}