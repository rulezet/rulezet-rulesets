rule TTP_XOR_MULT_DOSStub_6a51 {
  strings:
    $key_6a51 = { 3e 39 [2] 4a 21 [2] 0d 23 [2] 4a 32 [2] 04 3e [2] 08 34 [2] 1f 3f [2] 04 71 [2] 39 }

  condition:
    any of them
}