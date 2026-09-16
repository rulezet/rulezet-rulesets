rule TTP_XOR_MULT_DOSStub_c83d {
  strings:
    $key_c83d = { 9c 55 [2] e8 4d [2] af 4f [2] e8 5e [2] a6 52 [2] aa 58 [2] bd 53 [2] a6 1d [2] 9b }

  condition:
    any of them
}