rule TTP_XOR_MULT_DOSStub_5c3f {
  strings:
    $key_5c3f = { 08 57 [2] 7c 4f [2] 3b 4d [2] 7c 5c [2] 32 50 [2] 3e 5a [2] 29 51 [2] 32 1f [2] 0f }

  condition:
    any of them
}