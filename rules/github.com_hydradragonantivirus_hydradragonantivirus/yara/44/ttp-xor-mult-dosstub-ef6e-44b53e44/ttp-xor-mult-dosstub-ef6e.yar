rule TTP_XOR_MULT_DOSStub_ef6e {
  strings:
    $key_ef6e = { bb 06 [2] cf 1e [2] 88 1c [2] cf 0d [2] 81 01 [2] 8d 0b [2] 9a 00 [2] 81 4e [2] bc }

  condition:
    any of them
}