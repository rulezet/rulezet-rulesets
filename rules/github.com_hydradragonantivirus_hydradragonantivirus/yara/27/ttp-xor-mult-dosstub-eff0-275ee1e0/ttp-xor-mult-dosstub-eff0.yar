rule TTP_XOR_MULT_DOSStub_eff0 {
  strings:
    $key_eff0 = { bb 98 [2] cf 80 [2] 88 82 [2] cf 93 [2] 81 9f [2] 8d 95 [2] 9a 9e [2] 81 d0 [2] bc }

  condition:
    any of them
}