rule TTP_XOR_MULT_DOSStub_3c34 {
  strings:
    $key_3c34 = { 68 5c [2] 1c 44 [2] 5b 46 [2] 1c 57 [2] 52 5b [2] 5e 51 [2] 49 5a [2] 52 14 [2] 6f }

  condition:
    any of them
}