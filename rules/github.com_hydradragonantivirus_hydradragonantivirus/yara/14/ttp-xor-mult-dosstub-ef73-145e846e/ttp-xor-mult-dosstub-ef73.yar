rule TTP_XOR_MULT_DOSStub_ef73 {
  strings:
    $key_ef73 = { bb 1b [2] cf 03 [2] 88 01 [2] cf 10 [2] 81 1c [2] 8d 16 [2] 9a 1d [2] 81 53 [2] bc }

  condition:
    any of them
}