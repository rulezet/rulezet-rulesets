rule TTP_XOR_MULT_DOSStub_6631 {
  strings:
    $key_6631 = { 32 59 [2] 46 41 [2] 01 43 [2] 46 52 [2] 08 5e [2] 04 54 [2] 13 5f [2] 08 11 [2] 35 }

  condition:
    any of them
}