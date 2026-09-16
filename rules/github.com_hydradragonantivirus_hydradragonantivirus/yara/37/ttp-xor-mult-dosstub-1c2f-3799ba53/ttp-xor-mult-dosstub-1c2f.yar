rule TTP_XOR_MULT_DOSStub_1c2f {
  strings:
    $key_1c2f = { 48 47 [2] 3c 5f [2] 7b 5d [2] 3c 4c [2] 72 40 [2] 7e 4a [2] 69 41 [2] 72 0f [2] 4f }

  condition:
    any of them
}