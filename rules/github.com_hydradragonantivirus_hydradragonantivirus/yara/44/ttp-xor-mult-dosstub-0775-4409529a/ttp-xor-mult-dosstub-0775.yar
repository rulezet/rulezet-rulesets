rule TTP_XOR_MULT_DOSStub_0775 {
  strings:
    $key_0775 = { 53 1d [2] 27 05 [2] 60 07 [2] 27 16 [2] 69 1a [2] 65 10 [2] 72 1b [2] 69 55 [2] 54 }

  condition:
    any of them
}