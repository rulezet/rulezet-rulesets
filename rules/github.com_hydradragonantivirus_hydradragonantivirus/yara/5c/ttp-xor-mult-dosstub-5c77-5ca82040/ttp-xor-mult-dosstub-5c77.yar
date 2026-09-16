rule TTP_XOR_MULT_DOSStub_5c77 {
  strings:
    $key_5c77 = { 08 1f [2] 7c 07 [2] 3b 05 [2] 7c 14 [2] 32 18 [2] 3e 12 [2] 29 19 [2] 32 57 [2] 0f }

  condition:
    any of them
}