rule TTP_XOR_MULT_DOSStub_2fe1 {
  strings:
    $key_2fe1 = { 7b 89 [2] 0f 91 [2] 48 93 [2] 0f 82 [2] 41 8e [2] 4d 84 [2] 5a 8f [2] 41 c1 [2] 7c }

  condition:
    any of them
}