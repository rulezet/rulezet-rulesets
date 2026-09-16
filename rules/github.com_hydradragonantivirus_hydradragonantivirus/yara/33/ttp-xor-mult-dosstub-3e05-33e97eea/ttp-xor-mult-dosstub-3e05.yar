rule TTP_XOR_MULT_DOSStub_3e05 {
  strings:
    $key_3e05 = { 6a 6d [2] 1e 75 [2] 59 77 [2] 1e 66 [2] 50 6a [2] 5c 60 [2] 4b 6b [2] 50 25 [2] 6d }

  condition:
    any of them
}