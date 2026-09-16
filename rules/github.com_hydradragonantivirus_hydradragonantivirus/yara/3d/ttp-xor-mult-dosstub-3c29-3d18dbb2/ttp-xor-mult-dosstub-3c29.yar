rule TTP_XOR_MULT_DOSStub_3c29 {
  strings:
    $key_3c29 = { 68 41 [2] 1c 59 [2] 5b 5b [2] 1c 4a [2] 52 46 [2] 5e 4c [2] 49 47 [2] 52 09 [2] 6f }

  condition:
    any of them
}