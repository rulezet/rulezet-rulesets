rule TTP_XOR_MULT_DOSStub_1ae1 {
  strings:
    $key_1ae1 = { 4e 89 [2] 3a 91 [2] 7d 93 [2] 3a 82 [2] 74 8e [2] 78 84 [2] 6f 8f [2] 74 c1 [2] 49 }

  condition:
    any of them
}