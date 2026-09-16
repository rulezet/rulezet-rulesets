rule TTP_XOR_MULT_DOSStub_ef33 {
  strings:
    $key_ef33 = { bb 5b [2] cf 43 [2] 88 41 [2] cf 50 [2] 81 5c [2] 8d 56 [2] 9a 5d [2] 81 13 [2] bc }

  condition:
    any of them
}