rule TTP_XOR_MULT_DOSStub_c8ba {
  strings:
    $key_c8ba = { 9c d2 [2] e8 ca [2] af c8 [2] e8 d9 [2] a6 d5 [2] aa df [2] bd d4 [2] a6 9a [2] 9b }

  condition:
    any of them
}