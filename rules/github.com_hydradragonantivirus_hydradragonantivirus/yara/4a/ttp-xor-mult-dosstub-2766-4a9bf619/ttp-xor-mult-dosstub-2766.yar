rule TTP_XOR_MULT_DOSStub_2766 {
  strings:
    $key_2766 = { 73 0e [2] 07 16 [2] 40 14 [2] 07 05 [2] 49 09 [2] 45 03 [2] 52 08 [2] 49 46 [2] 74 }

  condition:
    any of them
}