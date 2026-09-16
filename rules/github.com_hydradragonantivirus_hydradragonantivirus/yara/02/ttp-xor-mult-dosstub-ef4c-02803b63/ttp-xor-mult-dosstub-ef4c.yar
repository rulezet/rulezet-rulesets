rule TTP_XOR_MULT_DOSStub_ef4c {
  strings:
    $key_ef4c = { bb 24 [2] cf 3c [2] 88 3e [2] cf 2f [2] 81 23 [2] 8d 29 [2] 9a 22 [2] 81 6c [2] bc }

  condition:
    any of them
}