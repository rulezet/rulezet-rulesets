rule TTP_XOR_MULT_DOSStub_3c15 {
  strings:
    $key_3c15 = { 68 7d [2] 1c 65 [2] 5b 67 [2] 1c 76 [2] 52 7a [2] 5e 70 [2] 49 7b [2] 52 35 [2] 6f }

  condition:
    any of them
}