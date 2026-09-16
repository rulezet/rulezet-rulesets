rule TTP_XOR_MULT_DOSStub_fe26 {
  strings:
    $key_fe26 = { aa 4e [2] de 56 [2] 99 54 [2] de 45 [2] 90 49 [2] 9c 43 [2] 8b 48 [2] 90 06 [2] ad }

  condition:
    any of them
}