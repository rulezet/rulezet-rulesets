rule TTP_XOR_MULT_DOSStub_3c33 {
  strings:
    $key_3c33 = { 68 5b [2] 1c 43 [2] 5b 41 [2] 1c 50 [2] 52 5c [2] 5e 56 [2] 49 5d [2] 52 13 [2] 6f }

  condition:
    any of them
}