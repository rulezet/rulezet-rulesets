rule TTP_XOR_MULT_DOSStub_7173 {
  strings:
    $key_7173 = { 25 1b [2] 51 03 [2] 16 01 [2] 51 10 [2] 1f 1c [2] 13 16 [2] 04 1d [2] 1f 53 [2] 22 }

  condition:
    any of them
}