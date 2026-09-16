rule TTP_XOR_MULT_DOSStub_6231 {
  strings:
    $key_6231 = { 36 59 [2] 42 41 [2] 05 43 [2] 42 52 [2] 0c 5e [2] 00 54 [2] 17 5f [2] 0c 11 [2] 31 }

  condition:
    any of them
}