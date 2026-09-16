rule TTP_XOR_MULT_DOSStub_3c13 {
  strings:
    $key_3c13 = { 68 7b [2] 1c 63 [2] 5b 61 [2] 1c 70 [2] 52 7c [2] 5e 76 [2] 49 7d [2] 52 33 [2] 6f }

  condition:
    any of them
}