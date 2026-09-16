rule TTP_XOR_MULT_DOSStub_3c19 {
  strings:
    $key_3c19 = { 68 71 [2] 1c 69 [2] 5b 6b [2] 1c 7a [2] 52 76 [2] 5e 7c [2] 49 77 [2] 52 39 [2] 6f }

  condition:
    any of them
}