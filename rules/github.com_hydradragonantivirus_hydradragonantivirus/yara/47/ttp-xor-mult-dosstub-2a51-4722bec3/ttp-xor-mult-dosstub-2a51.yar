rule TTP_XOR_MULT_DOSStub_2a51 {
  strings:
    $key_2a51 = { 7e 39 [2] 0a 21 [2] 4d 23 [2] 0a 32 [2] 44 3e [2] 48 34 [2] 5f 3f [2] 44 71 [2] 79 }

  condition:
    any of them
}