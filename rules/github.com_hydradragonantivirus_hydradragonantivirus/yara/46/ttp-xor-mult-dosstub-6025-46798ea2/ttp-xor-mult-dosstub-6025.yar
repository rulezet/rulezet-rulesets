rule TTP_XOR_MULT_DOSStub_6025 {
  strings:
    $key_6025 = { 34 4d [2] 40 55 [2] 07 57 [2] 40 46 [2] 0e 4a [2] 02 40 [2] 15 4b [2] 0e 05 [2] 33 }

  condition:
    any of them
}