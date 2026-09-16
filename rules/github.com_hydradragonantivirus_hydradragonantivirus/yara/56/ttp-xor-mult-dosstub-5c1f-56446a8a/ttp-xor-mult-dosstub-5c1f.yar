rule TTP_XOR_MULT_DOSStub_5c1f {
  strings:
    $key_5c1f = { 08 77 [2] 7c 6f [2] 3b 6d [2] 7c 7c [2] 32 70 [2] 3e 7a [2] 29 71 [2] 32 3f [2] 0f }

  condition:
    any of them
}