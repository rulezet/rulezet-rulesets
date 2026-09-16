rule TTP_XOR_MULT_DOSStub_3151 {
  strings:
    $key_3151 = { 65 39 [2] 11 21 [2] 56 23 [2] 11 32 [2] 5f 3e [2] 53 34 [2] 44 3f [2] 5f 71 [2] 62 }

  condition:
    any of them
}