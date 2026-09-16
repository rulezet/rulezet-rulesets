rule TTP_XOR_MULT_DOSStub_5e19 {
  strings:
    $key_5e19 = { 0a 71 [2] 7e 69 [2] 39 6b [2] 7e 7a [2] 30 76 [2] 3c 7c [2] 2b 77 [2] 30 39 [2] 0d }

  condition:
    any of them
}