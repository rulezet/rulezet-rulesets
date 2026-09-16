rule TTP_XOR_MULT_DOSStub_3be1 {
  strings:
    $key_3be1 = { 6f 89 [2] 1b 91 [2] 5c 93 [2] 1b 82 [2] 55 8e [2] 59 84 [2] 4e 8f [2] 55 c1 [2] 68 }

  condition:
    any of them
}