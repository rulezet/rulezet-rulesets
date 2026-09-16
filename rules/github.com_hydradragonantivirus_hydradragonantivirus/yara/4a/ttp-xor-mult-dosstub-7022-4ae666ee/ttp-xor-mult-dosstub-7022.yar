rule TTP_XOR_MULT_DOSStub_7022 {
  strings:
    $key_7022 = { 24 4a [2] 50 52 [2] 17 50 [2] 50 41 [2] 1e 4d [2] 12 47 [2] 05 4c [2] 1e 02 [2] 23 }

  condition:
    any of them
}