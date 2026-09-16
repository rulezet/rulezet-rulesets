rule TTP_XOR_MULT_DOSStub_035b {
  strings:
    $key_035b = { 57 33 [2] 23 2b [2] 64 29 [2] 23 38 [2] 6d 34 [2] 61 3e [2] 76 35 [2] 6d 7b [2] 50 }

  condition:
    any of them
}