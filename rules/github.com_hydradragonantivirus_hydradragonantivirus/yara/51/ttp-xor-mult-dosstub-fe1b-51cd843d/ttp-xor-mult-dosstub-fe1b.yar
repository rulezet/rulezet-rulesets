rule TTP_XOR_MULT_DOSStub_fe1b {
  strings:
    $key_fe1b = { aa 73 [2] de 6b [2] 99 69 [2] de 78 [2] 90 74 [2] 9c 7e [2] 8b 75 [2] 90 3b [2] ad }

  condition:
    any of them
}