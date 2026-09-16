rule TTP_XOR_MULT_DOSStub_4725 {
  strings:
    $key_4725 = { 13 4d [2] 67 55 [2] 20 57 [2] 67 46 [2] 29 4a [2] 25 40 [2] 32 4b [2] 29 05 [2] 14 }

  condition:
    any of them
}