rule TTP_XOR_MULT_DOSStub_eff7 {
  strings:
    $key_eff7 = { bb 9f [2] cf 87 [2] 88 85 [2] cf 94 [2] 81 98 [2] 8d 92 [2] 9a 99 [2] 81 d7 [2] bc }

  condition:
    any of them
}