rule TTP_XOR_MULT_DOSStub_3c22 {
  strings:
    $key_3c22 = { 68 4a [2] 1c 52 [2] 5b 50 [2] 1c 41 [2] 52 4d [2] 5e 47 [2] 49 4c [2] 52 02 [2] 6f }

  condition:
    any of them
}