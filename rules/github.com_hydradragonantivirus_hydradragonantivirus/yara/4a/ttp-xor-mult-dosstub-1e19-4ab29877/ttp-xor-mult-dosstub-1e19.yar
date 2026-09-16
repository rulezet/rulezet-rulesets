rule TTP_XOR_MULT_DOSStub_1e19 {
  strings:
    $key_1e19 = { 4a 71 [2] 3e 69 [2] 79 6b [2] 3e 7a [2] 70 76 [2] 7c 7c [2] 6b 77 [2] 70 39 [2] 4d }

  condition:
    any of them
}