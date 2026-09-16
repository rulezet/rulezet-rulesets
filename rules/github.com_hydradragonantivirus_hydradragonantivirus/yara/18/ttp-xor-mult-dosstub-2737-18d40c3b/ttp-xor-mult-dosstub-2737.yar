rule TTP_XOR_MULT_DOSStub_2737 {
  strings:
    $key_2737 = { 73 5f [2] 07 47 [2] 40 45 [2] 07 54 [2] 49 58 [2] 45 52 [2] 52 59 [2] 49 17 [2] 74 }

  condition:
    any of them
}