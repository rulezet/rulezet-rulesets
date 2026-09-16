rule TTP_XOR_MULT_DOSStub_5e14 {
  strings:
    $key_5e14 = { 0a 7c [2] 7e 64 [2] 39 66 [2] 7e 77 [2] 30 7b [2] 3c 71 [2] 2b 7a [2] 30 34 [2] 0d }

  condition:
    any of them
}