rule TTP_XOR_MULT_DOSStub_2e12 {
  strings:
    $key_2e12 = { 7a 7a [2] 0e 62 [2] 49 60 [2] 0e 71 [2] 40 7d [2] 4c 77 [2] 5b 7c [2] 40 32 [2] 7d }

  condition:
    any of them
}