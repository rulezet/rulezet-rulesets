rule TTP_XOR_MULT_DOSStub_7c2f {
  strings:
    $key_7c2f = { 28 47 [2] 5c 5f [2] 1b 5d [2] 5c 4c [2] 12 40 [2] 1e 4a [2] 09 41 [2] 12 0f [2] 2f }

  condition:
    any of them
}