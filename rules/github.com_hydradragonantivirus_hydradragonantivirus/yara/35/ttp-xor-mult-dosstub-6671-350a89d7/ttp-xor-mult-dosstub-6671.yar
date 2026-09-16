rule TTP_XOR_MULT_DOSStub_6671 {
  strings:
    $key_6671 = { 32 19 [2] 46 01 [2] 01 03 [2] 46 12 [2] 08 1e [2] 04 14 [2] 13 1f [2] 08 51 [2] 35 }

  condition:
    any of them
}