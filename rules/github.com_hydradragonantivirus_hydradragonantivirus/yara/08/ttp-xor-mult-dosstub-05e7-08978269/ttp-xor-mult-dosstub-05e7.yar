rule TTP_XOR_MULT_DOSStub_05e7 {
  strings:
    $key_05e7 = { 51 8f [2] 25 97 [2] 62 95 [2] 25 84 [2] 6b 88 [2] 67 82 [2] 70 89 [2] 6b c7 [2] 56 }

  condition:
    any of them
}