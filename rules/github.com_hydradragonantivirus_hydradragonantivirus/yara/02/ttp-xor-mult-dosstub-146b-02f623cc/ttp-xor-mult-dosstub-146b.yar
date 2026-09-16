rule TTP_XOR_MULT_DOSStub_146b {
  strings:
    $key_146b = { 40 03 [2] 34 1b [2] 73 19 [2] 34 08 [2] 7a 04 [2] 76 0e [2] 61 05 [2] 7a 4b [2] 47 }

  condition:
    any of them
}