rule TTP_XOR_MULT_DOSStub_fef6 {
  strings:
    $key_fef6 = { aa 9e [2] de 86 [2] 99 84 [2] de 95 [2] 90 99 [2] 9c 93 [2] 8b 98 [2] 90 d6 [2] ad }

  condition:
    any of them
}