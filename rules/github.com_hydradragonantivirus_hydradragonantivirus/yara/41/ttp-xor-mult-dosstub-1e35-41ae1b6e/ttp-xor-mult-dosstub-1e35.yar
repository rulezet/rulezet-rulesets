rule TTP_XOR_MULT_DOSStub_1e35 {
  strings:
    $key_1e35 = { 4a 5d [2] 3e 45 [2] 79 47 [2] 3e 56 [2] 70 5a [2] 7c 50 [2] 6b 5b [2] 70 15 [2] 4d }

  condition:
    any of them
}