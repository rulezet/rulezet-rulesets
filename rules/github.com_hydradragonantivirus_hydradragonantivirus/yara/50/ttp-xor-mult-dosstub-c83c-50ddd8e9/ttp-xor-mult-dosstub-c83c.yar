rule TTP_XOR_MULT_DOSStub_c83c {
  strings:
    $key_c83c = { 9c 54 [2] e8 4c [2] af 4e [2] e8 5f [2] a6 53 [2] aa 59 [2] bd 52 [2] a6 1c [2] 9b }

  condition:
    any of them
}