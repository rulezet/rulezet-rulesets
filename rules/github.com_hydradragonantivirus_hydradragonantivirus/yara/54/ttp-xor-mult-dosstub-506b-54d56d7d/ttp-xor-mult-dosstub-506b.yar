rule TTP_XOR_MULT_DOSStub_506b {
  strings:
    $key_506b = { 04 03 [2] 70 1b [2] 37 19 [2] 70 08 [2] 3e 04 [2] 32 0e [2] 25 05 [2] 3e 4b [2] 03 }

  condition:
    any of them
}