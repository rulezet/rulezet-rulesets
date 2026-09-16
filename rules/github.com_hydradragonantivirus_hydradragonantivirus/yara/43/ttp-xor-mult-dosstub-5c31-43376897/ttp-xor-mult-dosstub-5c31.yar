rule TTP_XOR_MULT_DOSStub_5c31 {
  strings:
    $key_5c31 = { 08 59 [2] 7c 41 [2] 3b 43 [2] 7c 52 [2] 32 5e [2] 3e 54 [2] 29 5f [2] 32 11 [2] 0f }

  condition:
    any of them
}