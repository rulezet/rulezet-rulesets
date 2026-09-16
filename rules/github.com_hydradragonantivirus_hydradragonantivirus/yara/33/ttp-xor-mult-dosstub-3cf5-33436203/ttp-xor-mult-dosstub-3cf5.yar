rule TTP_XOR_MULT_DOSStub_3cf5 {
  strings:
    $key_3cf5 = { 68 9d [2] 1c 85 [2] 5b 87 [2] 1c 96 [2] 52 9a [2] 5e 90 [2] 49 9b [2] 52 d5 [2] 6f }

  condition:
    any of them
}