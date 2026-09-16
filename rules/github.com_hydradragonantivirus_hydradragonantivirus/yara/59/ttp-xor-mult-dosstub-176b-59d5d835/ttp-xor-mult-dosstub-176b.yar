rule TTP_XOR_MULT_DOSStub_176b {
  strings:
    $key_176b = { 43 03 [2] 37 1b [2] 70 19 [2] 37 08 [2] 79 04 [2] 75 0e [2] 62 05 [2] 79 4b [2] 44 }

  condition:
    any of them
}