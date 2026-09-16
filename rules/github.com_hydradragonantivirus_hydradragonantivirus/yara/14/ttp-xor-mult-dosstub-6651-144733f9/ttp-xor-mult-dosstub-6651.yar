rule TTP_XOR_MULT_DOSStub_6651 {
  strings:
    $key_6651 = { 32 39 [2] 46 21 [2] 01 23 [2] 46 32 [2] 08 3e [2] 04 34 [2] 13 3f [2] 08 71 [2] 35 }

  condition:
    any of them
}