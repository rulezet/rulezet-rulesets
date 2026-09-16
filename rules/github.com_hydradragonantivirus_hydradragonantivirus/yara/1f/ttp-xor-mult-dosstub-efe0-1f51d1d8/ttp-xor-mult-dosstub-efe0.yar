rule TTP_XOR_MULT_DOSStub_efe0 {
  strings:
    $key_efe0 = { bb 88 [2] cf 90 [2] 88 92 [2] cf 83 [2] 81 8f [2] 8d 85 [2] 9a 8e [2] 81 c0 [2] bc }

  condition:
    any of them
}