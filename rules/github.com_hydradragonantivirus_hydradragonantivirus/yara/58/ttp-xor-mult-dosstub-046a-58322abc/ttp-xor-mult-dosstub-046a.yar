rule TTP_XOR_MULT_DOSStub_046a {
  strings:
    $key_046a = { 50 02 [2] 24 1a [2] 63 18 [2] 24 09 [2] 6a 05 [2] 66 0f [2] 71 04 [2] 6a 4a [2] 57 }

  condition:
    any of them
}