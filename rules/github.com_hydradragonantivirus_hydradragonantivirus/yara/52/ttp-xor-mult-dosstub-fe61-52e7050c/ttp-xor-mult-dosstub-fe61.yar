rule TTP_XOR_MULT_DOSStub_fe61 {
  strings:
    $key_fe61 = { aa 09 [2] de 11 [2] 99 13 [2] de 02 [2] 90 0e [2] 9c 04 [2] 8b 0f [2] 90 41 [2] ad }

  condition:
    any of them
}