rule TTP_XOR_MULT_DOSStub_c810 {
  strings:
    $key_c810 = { 9c 78 [2] e8 60 [2] af 62 [2] e8 73 [2] a6 7f [2] aa 75 [2] bd 7e [2] a6 30 [2] 9b }

  condition:
    any of them
}