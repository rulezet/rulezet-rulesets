rule TTP_XOR_MULT_DOSStub_3c04 {
  strings:
    $key_3c04 = { 68 6c [2] 1c 74 [2] 5b 76 [2] 1c 67 [2] 52 6b [2] 5e 61 [2] 49 6a [2] 52 24 [2] 6f }

  condition:
    any of them
}