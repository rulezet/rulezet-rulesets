rule TTP_XOR_MULT_DOSStub_046f {
  strings:
    $key_046f = { 50 07 [2] 24 1f [2] 63 1d [2] 24 0c [2] 6a 00 [2] 66 0a [2] 71 01 [2] 6a 4f [2] 57 }

  condition:
    any of them
}