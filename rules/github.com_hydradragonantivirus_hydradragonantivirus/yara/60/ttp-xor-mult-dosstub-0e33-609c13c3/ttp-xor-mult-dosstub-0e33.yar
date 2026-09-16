rule TTP_XOR_MULT_DOSStub_0e33 {
  strings:
    $key_0e33 = { 5a 5b [2] 2e 43 [2] 69 41 [2] 2e 50 [2] 60 5c [2] 6c 56 [2] 7b 5d [2] 60 13 [2] 5d }

  condition:
    any of them
}