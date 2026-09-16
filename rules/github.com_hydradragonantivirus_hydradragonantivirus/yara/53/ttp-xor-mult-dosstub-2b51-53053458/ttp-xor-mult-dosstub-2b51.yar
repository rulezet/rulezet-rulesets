rule TTP_XOR_MULT_DOSStub_2b51 {
  strings:
    $key_2b51 = { 7f 39 [2] 0b 21 [2] 4c 23 [2] 0b 32 [2] 45 3e [2] 49 34 [2] 5e 3f [2] 45 71 [2] 78 }

  condition:
    any of them
}