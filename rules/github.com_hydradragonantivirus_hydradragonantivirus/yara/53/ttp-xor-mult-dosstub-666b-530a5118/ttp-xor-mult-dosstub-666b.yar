rule TTP_XOR_MULT_DOSStub_666b {
  strings:
    $key_666b = { 32 03 [2] 46 1b [2] 01 19 [2] 46 08 [2] 08 04 [2] 04 0e [2] 13 05 [2] 08 4b [2] 35 }

  condition:
    any of them
}