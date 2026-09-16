rule TTP_XOR_MULT_DOSStub_5a51 {
  strings:
    $key_5a51 = { 0e 39 [2] 7a 21 [2] 3d 23 [2] 7a 32 [2] 34 3e [2] 38 34 [2] 2f 3f [2] 34 71 [2] 09 }

  condition:
    any of them
}