rule TTP_XOR_MULT_DOSStub_fe7d {
  strings:
    $key_fe7d = { aa 15 [2] de 0d [2] 99 0f [2] de 1e [2] 90 12 [2] 9c 18 [2] 8b 13 [2] 90 5d [2] ad }

  condition:
    any of them
}