rule TTP_XOR_MULT_DOSStub_2736 {
  strings:
    $key_2736 = { 73 5e [2] 07 46 [2] 40 44 [2] 07 55 [2] 49 59 [2] 45 53 [2] 52 58 [2] 49 16 [2] 74 }

  condition:
    any of them
}