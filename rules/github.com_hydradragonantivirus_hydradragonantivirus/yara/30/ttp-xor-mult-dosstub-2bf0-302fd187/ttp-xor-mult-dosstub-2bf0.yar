rule TTP_XOR_MULT_DOSStub_2bf0 {
  strings:
    $key_2bf0 = { 7f 98 [2] 0b 80 [2] 4c 82 [2] 0b 93 [2] 45 9f [2] 49 95 [2] 5e 9e [2] 45 d0 [2] 78 }

  condition:
    any of them
}