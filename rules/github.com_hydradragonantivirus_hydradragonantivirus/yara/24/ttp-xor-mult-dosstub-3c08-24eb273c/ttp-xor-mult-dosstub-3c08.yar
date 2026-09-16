rule TTP_XOR_MULT_DOSStub_3c08 {
  strings:
    $key_3c08 = { 68 60 [2] 1c 78 [2] 5b 7a [2] 1c 6b [2] 52 67 [2] 5e 6d [2] 49 66 [2] 52 28 [2] 6f }

  condition:
    any of them
}