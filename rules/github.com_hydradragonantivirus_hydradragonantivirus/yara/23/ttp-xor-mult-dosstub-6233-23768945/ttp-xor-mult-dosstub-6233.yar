rule TTP_XOR_MULT_DOSStub_6233 {
  strings:
    $key_6233 = { 36 5b [2] 42 43 [2] 05 41 [2] 42 50 [2] 0c 5c [2] 00 56 [2] 17 5d [2] 0c 13 [2] 31 }

  condition:
    any of them
}