rule TTP_XOR_MULT_DOSStub_2173 {
  strings:
    $key_2173 = { 75 1b [2] 01 03 [2] 46 01 [2] 01 10 [2] 4f 1c [2] 43 16 [2] 54 1d [2] 4f 53 [2] 72 }

  condition:
    any of them
}