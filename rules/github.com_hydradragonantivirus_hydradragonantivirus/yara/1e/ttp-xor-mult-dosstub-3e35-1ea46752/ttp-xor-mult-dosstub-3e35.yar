rule TTP_XOR_MULT_DOSStub_3e35 {
  strings:
    $key_3e35 = { 6a 5d [2] 1e 45 [2] 59 47 [2] 1e 56 [2] 50 5a [2] 5c 50 [2] 4b 5b [2] 50 15 [2] 6d }

  condition:
    any of them
}