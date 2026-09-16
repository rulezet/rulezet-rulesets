rule TTP_XOR_MULT_DOSStub_5c3c {
  strings:
    $key_5c3c = { 08 54 [2] 7c 4c [2] 3b 4e [2] 7c 5f [2] 32 53 [2] 3e 59 [2] 29 52 [2] 32 1c [2] 0f }

  condition:
    any of them
}