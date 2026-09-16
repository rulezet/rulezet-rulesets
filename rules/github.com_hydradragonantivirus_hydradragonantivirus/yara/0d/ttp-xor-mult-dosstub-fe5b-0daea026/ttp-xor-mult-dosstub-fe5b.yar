rule TTP_XOR_MULT_DOSStub_fe5b {
  strings:
    $key_fe5b = { aa 33 [2] de 2b [2] 99 29 [2] de 38 [2] 90 34 [2] 9c 3e [2] 8b 35 [2] 90 7b [2] ad }

  condition:
    any of them
}