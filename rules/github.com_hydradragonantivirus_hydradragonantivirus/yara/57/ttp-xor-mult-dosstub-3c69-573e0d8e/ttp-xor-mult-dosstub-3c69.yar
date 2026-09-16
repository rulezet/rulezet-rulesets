rule TTP_XOR_MULT_DOSStub_3c69 {
  strings:
    $key_3c69 = { 68 01 [2] 1c 19 [2] 5b 1b [2] 1c 0a [2] 52 06 [2] 5e 0c [2] 49 07 [2] 52 49 [2] 6f }

  condition:
    any of them
}