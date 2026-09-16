rule TTP_XOR_MULT_DOSStub_1e14 {
  strings:
    $key_1e14 = { 4a 7c [2] 3e 64 [2] 79 66 [2] 3e 77 [2] 70 7b [2] 7c 71 [2] 6b 7a [2] 70 34 [2] 4d }

  condition:
    any of them
}