rule TTP_XOR_MULT_DOSStub_3be7 {
  strings:
    $key_3be7 = { 6f 8f [2] 1b 97 [2] 5c 95 [2] 1b 84 [2] 55 88 [2] 59 82 [2] 4e 89 [2] 55 c7 [2] 68 }

  condition:
    any of them
}