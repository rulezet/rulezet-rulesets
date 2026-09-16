rule TTP_XOR_MULT_DOSStub_513b {
  strings:
    $key_513b = { 05 53 [2] 71 4b [2] 36 49 [2] 71 58 [2] 3f 54 [2] 33 5e [2] 24 55 [2] 3f 1b [2] 02 }

  condition:
    any of them
}