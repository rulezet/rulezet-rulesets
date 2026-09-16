rule TTP_XOR_MULT_DOSStub_68e1 {
  strings:
    $key_68e1 = { 3c 89 [2] 48 91 [2] 0f 93 [2] 48 82 [2] 06 8e [2] 0a 84 [2] 1d 8f [2] 06 c1 [2] 3b }

  condition:
    any of them
}