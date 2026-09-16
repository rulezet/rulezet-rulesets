rule TTP_XOR_MULT_DOSStub_3c63 {
  strings:
    $key_3c63 = { 68 0b [2] 1c 13 [2] 5b 11 [2] 1c 00 [2] 52 0c [2] 5e 06 [2] 49 0d [2] 52 43 [2] 6f }

  condition:
    any of them
}