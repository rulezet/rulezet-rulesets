rule TTP_XOR_MULT_DOSStub_5f56 {
  strings:
    $key_5f56 = { 0b 3e [2] 7f 26 [2] 38 24 [2] 7f 35 [2] 31 39 [2] 3d 33 [2] 2a 38 [2] 31 76 [2] 0c }

  condition:
    any of them
}