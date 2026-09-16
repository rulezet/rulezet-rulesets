rule TTP_XOR_MULT_DOSStub_636b {
  strings:
    $key_636b = { 37 03 [2] 43 1b [2] 04 19 [2] 43 08 [2] 0d 04 [2] 01 0e [2] 16 05 [2] 0d 4b [2] 30 }

  condition:
    any of them
}