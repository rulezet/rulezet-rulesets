rule TTP_XOR_MULT_DOSStub_12e1 {
  strings:
    $key_12e1 = { 46 89 [2] 32 91 [2] 75 93 [2] 32 82 [2] 7c 8e [2] 70 84 [2] 67 8f [2] 7c c1 [2] 41 }

  condition:
    any of them
}