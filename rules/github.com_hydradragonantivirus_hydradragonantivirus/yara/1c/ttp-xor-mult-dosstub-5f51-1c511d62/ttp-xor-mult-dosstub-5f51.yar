rule TTP_XOR_MULT_DOSStub_5f51 {
  strings:
    $key_5f51 = { 0b 39 [2] 7f 21 [2] 38 23 [2] 7f 32 [2] 31 3e [2] 3d 34 [2] 2a 3f [2] 31 71 [2] 0c }

  condition:
    any of them
}