rule TTP_XOR_MULT_DOSStub_fe40 {
  strings:
    $key_fe40 = { aa 28 [2] de 30 [2] 99 32 [2] de 23 [2] 90 2f [2] 9c 25 [2] 8b 2e [2] 90 60 [2] ad }

  condition:
    any of them
}