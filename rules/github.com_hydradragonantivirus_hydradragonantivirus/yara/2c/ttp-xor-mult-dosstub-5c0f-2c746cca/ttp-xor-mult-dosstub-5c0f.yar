rule TTP_XOR_MULT_DOSStub_5c0f {
  strings:
    $key_5c0f = { 08 67 [2] 7c 7f [2] 3b 7d [2] 7c 6c [2] 32 60 [2] 3e 6a [2] 29 61 [2] 32 2f [2] 0f }

  condition:
    any of them
}