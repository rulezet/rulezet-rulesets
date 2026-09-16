rule TTP_XOR_MULT_DOSStub_ef1e {
  strings:
    $key_ef1e = { bb 76 [2] cf 6e [2] 88 6c [2] cf 7d [2] 81 71 [2] 8d 7b [2] 9a 70 [2] 81 3e [2] bc }

  condition:
    any of them
}