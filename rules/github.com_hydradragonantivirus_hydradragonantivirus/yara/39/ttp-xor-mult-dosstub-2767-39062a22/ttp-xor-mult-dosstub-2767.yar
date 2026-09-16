rule TTP_XOR_MULT_DOSStub_2767 {
  strings:
    $key_2767 = { 73 0f [2] 07 17 [2] 40 15 [2] 07 04 [2] 49 08 [2] 45 02 [2] 52 09 [2] 49 47 [2] 74 }

  condition:
    any of them
}