rule TTP_XOR_MULT_DOSStub_1c2b {
  strings:
    $key_1c2b = { 48 43 [2] 3c 5b [2] 7b 59 [2] 3c 48 [2] 72 44 [2] 7e 4e [2] 69 45 [2] 72 0b [2] 4f }

  condition:
    any of them
}