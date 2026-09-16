rule TTP_XOR_MULT_DOSStub_ef3d {
  strings:
    $key_ef3d = { bb 55 [2] cf 4d [2] 88 4f [2] cf 5e [2] 81 52 [2] 8d 58 [2] 9a 53 [2] 81 1d [2] bc }

  condition:
    any of them
}