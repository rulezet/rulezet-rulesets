rule TTP_XOR_MULT_DOSStub_3775 {
  strings:
    $key_3775 = { 63 1d [2] 17 05 [2] 50 07 [2] 17 16 [2] 59 1a [2] 55 10 [2] 42 1b [2] 59 55 [2] 64 }

  condition:
    any of them
}