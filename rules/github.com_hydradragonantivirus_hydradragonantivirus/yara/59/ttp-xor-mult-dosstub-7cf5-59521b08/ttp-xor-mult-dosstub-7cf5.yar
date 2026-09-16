rule TTP_XOR_MULT_DOSStub_7cf5 {
  strings:
    $key_7cf5 = { 28 9d [2] 5c 85 [2] 1b 87 [2] 5c 96 [2] 12 9a [2] 1e 90 [2] 09 9b [2] 12 d5 [2] 2f }

  condition:
    any of them
}