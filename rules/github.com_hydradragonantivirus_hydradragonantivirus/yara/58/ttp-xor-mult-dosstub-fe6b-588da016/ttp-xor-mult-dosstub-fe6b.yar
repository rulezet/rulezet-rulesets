rule TTP_XOR_MULT_DOSStub_fe6b {
  strings:
    $key_fe6b = { aa 03 [2] de 1b [2] 99 19 [2] de 08 [2] 90 04 [2] 9c 0e [2] 8b 05 [2] 90 4b [2] ad }

  condition:
    any of them
}