rule TTP_XOR_MULT_DOSStub_5c2f {
  strings:
    $key_5c2f = { 08 47 [2] 7c 5f [2] 3b 5d [2] 7c 4c [2] 32 40 [2] 3e 4a [2] 29 41 [2] 32 0f [2] 0f }

  condition:
    any of them
}