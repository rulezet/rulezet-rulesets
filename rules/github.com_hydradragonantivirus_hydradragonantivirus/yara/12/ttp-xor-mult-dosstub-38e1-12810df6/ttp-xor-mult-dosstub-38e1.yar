rule TTP_XOR_MULT_DOSStub_38e1 {
  strings:
    $key_38e1 = { 6c 89 [2] 18 91 [2] 5f 93 [2] 18 82 [2] 56 8e [2] 5a 84 [2] 4d 8f [2] 56 c1 [2] 6b }

  condition:
    any of them
}