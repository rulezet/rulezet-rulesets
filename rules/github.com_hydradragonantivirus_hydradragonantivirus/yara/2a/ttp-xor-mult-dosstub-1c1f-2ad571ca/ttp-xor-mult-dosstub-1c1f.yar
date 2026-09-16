rule TTP_XOR_MULT_DOSStub_1c1f {
  strings:
    $key_1c1f = { 48 77 [2] 3c 6f [2] 7b 6d [2] 3c 7c [2] 72 70 [2] 7e 7a [2] 69 71 [2] 72 3f [2] 4f }

  condition:
    any of them
}