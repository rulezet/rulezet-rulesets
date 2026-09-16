rule TTP_XOR_MULT_DOSStub_3ce7 {
  strings:
    $key_3ce7 = { 68 8f [2] 1c 97 [2] 5b 95 [2] 1c 84 [2] 52 88 [2] 5e 82 [2] 49 89 [2] 52 c7 [2] 6f }

  condition:
    any of them
}