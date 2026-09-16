rule TTP_XOR_MULT_DOSStub_5c7f {
  strings:
    $key_5c7f = { 08 17 [2] 7c 0f [2] 3b 0d [2] 7c 1c [2] 32 10 [2] 3e 1a [2] 29 11 [2] 32 5f [2] 0f }

  condition:
    any of them
}