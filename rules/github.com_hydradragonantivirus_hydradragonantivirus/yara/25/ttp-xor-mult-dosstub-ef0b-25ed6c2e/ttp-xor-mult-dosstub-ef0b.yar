rule TTP_XOR_MULT_DOSStub_ef0b {
  strings:
    $key_ef0b = { bb 63 [2] cf 7b [2] 88 79 [2] cf 68 [2] 81 64 [2] 8d 6e [2] 9a 65 [2] 81 2b [2] bc }

  condition:
    any of them
}