rule TTP_XOR_MULT_DOSStub_ef67 {
  strings:
    $key_ef67 = { bb 0f [2] cf 17 [2] 88 15 [2] cf 04 [2] 81 08 [2] 8d 02 [2] 9a 09 [2] 81 47 [2] bc }

  condition:
    any of them
}