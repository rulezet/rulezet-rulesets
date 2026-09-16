rule TTP_XOR_MULT_DOSStub_ef1d {
  strings:
    $key_ef1d = { bb 75 [2] cf 6d [2] 88 6f [2] cf 7e [2] 81 72 [2] 8d 78 [2] 9a 73 [2] 81 3d [2] bc }

  condition:
    any of them
}