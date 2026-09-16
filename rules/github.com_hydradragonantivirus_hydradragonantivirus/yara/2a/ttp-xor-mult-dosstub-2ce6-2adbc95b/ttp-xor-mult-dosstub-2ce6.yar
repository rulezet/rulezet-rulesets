rule TTP_XOR_MULT_DOSStub_2ce6 {
  strings:
    $key_2ce6 = { 78 8e [2] 0c 96 [2] 4b 94 [2] 0c 85 [2] 42 89 [2] 4e 83 [2] 59 88 [2] 42 c6 [2] 7f }

  condition:
    any of them
}