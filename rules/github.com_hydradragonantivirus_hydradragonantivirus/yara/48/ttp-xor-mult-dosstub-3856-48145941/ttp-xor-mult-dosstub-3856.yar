rule TTP_XOR_MULT_DOSStub_3856 {
  strings:
    $key_3856 = { 6c 3e [2] 18 26 [2] 5f 24 [2] 18 35 [2] 56 39 [2] 5a 33 [2] 4d 38 [2] 56 76 [2] 6b }

  condition:
    any of them
}