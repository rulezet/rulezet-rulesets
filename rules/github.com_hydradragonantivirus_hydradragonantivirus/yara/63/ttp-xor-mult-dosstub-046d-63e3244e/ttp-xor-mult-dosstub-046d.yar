rule TTP_XOR_MULT_DOSStub_046d {
  strings:
    $key_046d = { 50 05 [2] 24 1d [2] 63 1f [2] 24 0e [2] 6a 02 [2] 66 08 [2] 71 03 [2] 6a 4d [2] 57 }

  condition:
    any of them
}