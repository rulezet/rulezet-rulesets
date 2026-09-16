rule TTP_XOR_MULT_DOSStub_006b {
  strings:
    $key_006b = { 54 03 [2] 20 1b [2] 67 19 [2] 20 08 [2] 6e 04 [2] 62 0e [2] 75 05 [2] 6e 4b [2] 53 }

  condition:
    any of them
}