rule TTP_XOR_MULT_DOSStub_7de1 {
  strings:
    $key_7de1 = { 29 89 [2] 5d 91 [2] 1a 93 [2] 5d 82 [2] 13 8e [2] 1f 84 [2] 08 8f [2] 13 c1 [2] 2e }

  condition:
    any of them
}