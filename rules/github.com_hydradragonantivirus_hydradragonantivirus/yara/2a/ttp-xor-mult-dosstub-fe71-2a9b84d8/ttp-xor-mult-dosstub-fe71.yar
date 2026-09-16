rule TTP_XOR_MULT_DOSStub_fe71 {
  strings:
    $key_fe71 = { aa 19 [2] de 01 [2] 99 03 [2] de 12 [2] 90 1e [2] 9c 14 [2] 8b 1f [2] 90 51 [2] ad }

  condition:
    any of them
}