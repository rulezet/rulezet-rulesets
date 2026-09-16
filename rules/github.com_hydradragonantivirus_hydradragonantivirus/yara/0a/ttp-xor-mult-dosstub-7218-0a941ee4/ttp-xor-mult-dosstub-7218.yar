rule TTP_XOR_MULT_DOSStub_7218 {
  strings:
    $key_7218 = { 26 70 [2] 52 68 [2] 15 6a [2] 52 7b [2] 1c 77 [2] 10 7d [2] 07 76 [2] 1c 38 [2] 21 }

  condition:
    any of them
}