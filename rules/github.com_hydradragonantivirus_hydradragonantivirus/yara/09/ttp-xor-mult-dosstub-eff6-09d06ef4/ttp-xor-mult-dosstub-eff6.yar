rule TTP_XOR_MULT_DOSStub_eff6 {
  strings:
    $key_eff6 = { bb 9e [2] cf 86 [2] 88 84 [2] cf 95 [2] 81 99 [2] 8d 93 [2] 9a 98 [2] 81 d6 [2] bc }

  condition:
    any of them
}