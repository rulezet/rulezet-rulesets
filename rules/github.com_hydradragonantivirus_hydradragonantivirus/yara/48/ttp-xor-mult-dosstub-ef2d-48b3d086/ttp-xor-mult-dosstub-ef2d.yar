rule TTP_XOR_MULT_DOSStub_ef2d {
  strings:
    $key_ef2d = { bb 45 [2] cf 5d [2] 88 5f [2] cf 4e [2] 81 42 [2] 8d 48 [2] 9a 43 [2] 81 0d [2] bc }

  condition:
    any of them
}