rule TTP_XOR_MULT_DOSStub_5e12 {
  strings:
    $key_5e12 = { 0a 7a [2] 7e 62 [2] 39 60 [2] 7e 71 [2] 30 7d [2] 3c 77 [2] 2b 7c [2] 30 32 [2] 0d }

  condition:
    any of them
}