rule TTP_XOR_MULT_DOSStub_217b {
  strings:
    $key_217b = { 75 13 [2] 01 0b [2] 46 09 [2] 01 18 [2] 4f 14 [2] 43 1e [2] 54 15 [2] 4f 5b [2] 72 }

  condition:
    any of them
}