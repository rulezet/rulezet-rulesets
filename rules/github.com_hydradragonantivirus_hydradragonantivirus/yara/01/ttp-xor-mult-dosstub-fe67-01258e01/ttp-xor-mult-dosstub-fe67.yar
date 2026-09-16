rule TTP_XOR_MULT_DOSStub_fe67 {
  strings:
    $key_fe67 = { aa 0f [2] de 17 [2] 99 15 [2] de 04 [2] 90 08 [2] 9c 02 [2] 8b 09 [2] 90 47 [2] ad }

  condition:
    any of them
}