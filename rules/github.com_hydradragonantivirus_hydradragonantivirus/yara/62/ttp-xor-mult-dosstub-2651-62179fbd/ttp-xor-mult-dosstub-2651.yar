rule TTP_XOR_MULT_DOSStub_2651 {
  strings:
    $key_2651 = { 72 39 [2] 06 21 [2] 41 23 [2] 06 32 [2] 48 3e [2] 44 34 [2] 53 3f [2] 48 71 [2] 75 }

  condition:
    any of them
}