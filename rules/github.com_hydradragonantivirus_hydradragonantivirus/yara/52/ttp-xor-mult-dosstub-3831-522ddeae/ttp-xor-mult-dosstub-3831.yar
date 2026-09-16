rule TTP_XOR_MULT_DOSStub_3831 {
  strings:
    $key_3831 = { 6c 59 [2] 18 41 [2] 5f 43 [2] 18 52 [2] 56 5e [2] 5a 54 [2] 4d 5f [2] 56 11 [2] 6b }

  condition:
    any of them
}