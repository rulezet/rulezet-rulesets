rule TTP_XOR_MULT_DOSStub_3c24 {
  strings:
    $key_3c24 = { 68 4c [2] 1c 54 [2] 5b 56 [2] 1c 47 [2] 52 4b [2] 5e 41 [2] 49 4a [2] 52 04 [2] 6f }

  condition:
    any of them
}