rule TTP_XOR_MULT_DOSStub_3850 {
  strings:
    $key_3850 = { 6c 38 [2] 18 20 [2] 5f 22 [2] 18 33 [2] 56 3f [2] 5a 35 [2] 4d 3e [2] 56 70 [2] 6b }

  condition:
    any of them
}