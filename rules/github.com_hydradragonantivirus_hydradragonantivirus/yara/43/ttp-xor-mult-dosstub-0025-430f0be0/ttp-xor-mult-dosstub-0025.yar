rule TTP_XOR_MULT_DOSStub_0025 {
  strings:
    $key_0025 = { 54 4d [2] 20 55 [2] 67 57 [2] 20 46 [2] 6e 4a [2] 62 40 [2] 75 4b [2] 6e 05 [2] 53 }

  condition:
    any of them
}