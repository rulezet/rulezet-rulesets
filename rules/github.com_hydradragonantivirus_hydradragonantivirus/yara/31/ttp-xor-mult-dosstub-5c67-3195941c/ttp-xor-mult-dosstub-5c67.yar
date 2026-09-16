rule TTP_XOR_MULT_DOSStub_5c67 {
  strings:
    $key_5c67 = { 08 0f [2] 7c 17 [2] 3b 15 [2] 7c 04 [2] 32 08 [2] 3e 02 [2] 29 09 [2] 32 47 [2] 0f }

  condition:
    any of them
}