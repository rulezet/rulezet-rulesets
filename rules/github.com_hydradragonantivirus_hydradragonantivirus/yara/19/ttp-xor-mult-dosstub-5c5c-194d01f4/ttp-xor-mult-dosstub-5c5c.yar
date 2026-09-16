rule TTP_XOR_MULT_DOSStub_5c5c {
  strings:
    $key_5c5c = { 08 34 [2] 7c 2c [2] 3b 2e [2] 7c 3f [2] 32 33 [2] 3e 39 [2] 29 32 [2] 32 7c [2] 0f }

  condition:
    any of them
}