rule TTP_XOR_MULT_DOSStub_78e1 {
  strings:
    $key_78e1 = { 2c 89 [2] 58 91 [2] 1f 93 [2] 58 82 [2] 16 8e [2] 1a 84 [2] 0d 8f [2] 16 c1 [2] 2b }

  condition:
    any of them
}