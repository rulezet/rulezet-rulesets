rule TTP_XOR_MULT_DOSStub_c80c {
  strings:
    $key_c80c = { 9c 64 [2] e8 7c [2] af 7e [2] e8 6f [2] a6 63 [2] aa 69 [2] bd 62 [2] a6 2c [2] 9b }

  condition:
    any of them
}