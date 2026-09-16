rule TTP_XOR_MULT_DOSStub_2726 {
  strings:
    $key_2726 = { 73 4e [2] 07 56 [2] 40 54 [2] 07 45 [2] 49 49 [2] 45 43 [2] 52 48 [2] 49 06 [2] 74 }

  condition:
    any of them
}