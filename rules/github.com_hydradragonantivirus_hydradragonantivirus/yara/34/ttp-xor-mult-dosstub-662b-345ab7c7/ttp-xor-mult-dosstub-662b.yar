rule TTP_XOR_MULT_DOSStub_662b {
  strings:
    $key_662b = { 32 43 [2] 46 5b [2] 01 59 [2] 46 48 [2] 08 44 [2] 04 4e [2] 13 45 [2] 08 0b [2] 35 }

  condition:
    any of them
}