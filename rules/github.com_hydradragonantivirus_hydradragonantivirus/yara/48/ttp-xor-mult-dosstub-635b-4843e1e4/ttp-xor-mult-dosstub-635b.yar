rule TTP_XOR_MULT_DOSStub_635b {
  strings:
    $key_635b = { 37 33 [2] 43 2b [2] 04 29 [2] 43 38 [2] 0d 34 [2] 01 3e [2] 16 35 [2] 0d 7b [2] 30 }

  condition:
    any of them
}