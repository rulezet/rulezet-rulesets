rule TTP_XOR_MULT_DOSStub_ef35 {
  strings:
    $key_ef35 = { bb 5d [2] cf 45 [2] 88 47 [2] cf 56 [2] 81 5a [2] 8d 50 [2] 9a 5b [2] 81 15 [2] bc }

  condition:
    any of them
}