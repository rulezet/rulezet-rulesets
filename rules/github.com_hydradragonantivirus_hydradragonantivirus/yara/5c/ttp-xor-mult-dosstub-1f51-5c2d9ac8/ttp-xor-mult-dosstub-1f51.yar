rule TTP_XOR_MULT_DOSStub_1f51 {
  strings:
    $key_1f51 = { 4b 39 [2] 3f 21 [2] 78 23 [2] 3f 32 [2] 71 3e [2] 7d 34 [2] 6a 3f [2] 71 71 [2] 4c }

  condition:
    any of them
}