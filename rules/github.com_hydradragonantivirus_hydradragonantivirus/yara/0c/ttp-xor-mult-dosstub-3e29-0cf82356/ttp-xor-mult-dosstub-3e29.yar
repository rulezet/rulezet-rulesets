rule TTP_XOR_MULT_DOSStub_3e29 {
  strings:
    $key_3e29 = { 6a 41 [2] 1e 59 [2] 59 5b [2] 1e 4a [2] 50 46 [2] 5c 4c [2] 4b 47 [2] 50 09 [2] 6d }

  condition:
    any of them
}