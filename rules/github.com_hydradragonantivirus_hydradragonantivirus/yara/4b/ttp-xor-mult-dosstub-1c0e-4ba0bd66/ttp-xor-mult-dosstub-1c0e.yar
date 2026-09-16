rule TTP_XOR_MULT_DOSStub_1c0e {
  strings:
    $key_1c0e = { 48 66 [2] 3c 7e [2] 7b 7c [2] 3c 6d [2] 72 61 [2] 7e 6b [2] 69 60 [2] 72 2e [2] 4f }

  condition:
    any of them
}