rule TTP_XOR_MULT_DOSStub_667c {
  strings:
    $key_667c = { 32 14 [2] 46 0c [2] 01 0e [2] 46 1f [2] 08 13 [2] 04 19 [2] 13 12 [2] 08 5c [2] 35 }

  condition:
    any of them
}