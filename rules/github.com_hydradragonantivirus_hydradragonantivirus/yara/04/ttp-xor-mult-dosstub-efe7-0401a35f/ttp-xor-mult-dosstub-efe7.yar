rule TTP_XOR_MULT_DOSStub_efe7 {
  strings:
    $key_efe7 = { bb 8f [2] cf 97 [2] 88 95 [2] cf 84 [2] 81 88 [2] 8d 82 [2] 9a 89 [2] 81 c7 [2] bc }

  condition:
    any of them
}