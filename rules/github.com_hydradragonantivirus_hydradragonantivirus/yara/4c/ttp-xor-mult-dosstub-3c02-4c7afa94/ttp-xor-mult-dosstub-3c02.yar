rule TTP_XOR_MULT_DOSStub_3c02 {
  strings:
    $key_3c02 = { 68 6a [2] 1c 72 [2] 5b 70 [2] 1c 61 [2] 52 6d [2] 5e 67 [2] 49 6c [2] 52 22 [2] 6f }

  condition:
    any of them
}