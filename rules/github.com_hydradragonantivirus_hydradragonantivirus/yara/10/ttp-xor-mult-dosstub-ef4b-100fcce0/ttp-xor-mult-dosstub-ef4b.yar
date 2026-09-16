rule TTP_XOR_MULT_DOSStub_ef4b {
  strings:
    $key_ef4b = { bb 23 [2] cf 3b [2] 88 39 [2] cf 28 [2] 81 24 [2] 8d 2e [2] 9a 25 [2] 81 6b [2] bc }

  condition:
    any of them
}