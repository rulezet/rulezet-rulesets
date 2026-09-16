rule TTP_XOR_MULT_DOSStub_3f51 {
  strings:
    $key_3f51 = { 6b 39 [2] 1f 21 [2] 58 23 [2] 1f 32 [2] 51 3e [2] 5d 34 [2] 4a 3f [2] 51 71 [2] 6c }

  condition:
    any of them
}