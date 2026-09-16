rule TTP_XOR_MULT_DOSStub_2be7 {
  strings:
    $key_2be7 = { 7f 8f [2] 0b 97 [2] 4c 95 [2] 0b 84 [2] 45 88 [2] 49 82 [2] 5e 89 [2] 45 c7 [2] 78 }

  condition:
    any of them
}