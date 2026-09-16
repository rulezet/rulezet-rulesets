rule TTP_XOR_MULT_DOSStub_4775 {
  strings:
    $key_4775 = { 13 1d [2] 67 05 [2] 20 07 [2] 67 16 [2] 29 1a [2] 25 10 [2] 32 1b [2] 29 55 [2] 14 }

  condition:
    any of them
}