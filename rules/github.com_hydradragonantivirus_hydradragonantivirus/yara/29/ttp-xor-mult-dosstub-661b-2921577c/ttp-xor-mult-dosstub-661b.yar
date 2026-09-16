rule TTP_XOR_MULT_DOSStub_661b {
  strings:
    $key_661b = { 32 73 [2] 46 6b [2] 01 69 [2] 46 78 [2] 08 74 [2] 04 7e [2] 13 75 [2] 08 3b [2] 35 }

  condition:
    any of them
}