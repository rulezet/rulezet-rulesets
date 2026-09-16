rule TTP_XOR_MULT_DOSStub_147b {
  strings:
    $key_147b = { 40 13 [2] 34 0b [2] 73 09 [2] 34 18 [2] 7a 14 [2] 76 1e [2] 61 15 [2] 7a 5b [2] 47 }

  condition:
    any of them
}