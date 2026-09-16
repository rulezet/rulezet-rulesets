rule TTP_XOR_MULT_DOSStub_3c23 {
  strings:
    $key_3c23 = { 68 4b [2] 1c 53 [2] 5b 51 [2] 1c 40 [2] 52 4c [2] 5e 46 [2] 49 4d [2] 52 03 [2] 6f }

  condition:
    any of them
}