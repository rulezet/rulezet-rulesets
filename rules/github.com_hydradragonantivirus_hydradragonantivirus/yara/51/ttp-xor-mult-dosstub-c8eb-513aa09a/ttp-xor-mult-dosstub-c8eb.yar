rule TTP_XOR_MULT_DOSStub_c8eb {
  strings:
    $key_c8eb = { 9c 83 [2] e8 9b [2] af 99 [2] e8 88 [2] a6 84 [2] aa 8e [2] bd 85 [2] a6 cb [2] 9b }

  condition:
    any of them
}