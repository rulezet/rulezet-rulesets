rule TTP_XOR_MULT_DOSStub_ef0c {
  strings:
    $key_ef0c = { bb 64 [2] cf 7c [2] 88 7e [2] cf 6f [2] 81 63 [2] 8d 69 [2] 9a 62 [2] 81 2c [2] bc }

  condition:
    any of them
}