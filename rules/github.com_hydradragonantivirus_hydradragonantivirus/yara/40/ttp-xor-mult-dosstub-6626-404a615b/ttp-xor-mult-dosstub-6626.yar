rule TTP_XOR_MULT_DOSStub_6626 {
  strings:
    $key_6626 = { 32 4e [2] 46 56 [2] 01 54 [2] 46 45 [2] 08 49 [2] 04 43 [2] 13 48 [2] 08 06 [2] 35 }

  condition:
    any of them
}