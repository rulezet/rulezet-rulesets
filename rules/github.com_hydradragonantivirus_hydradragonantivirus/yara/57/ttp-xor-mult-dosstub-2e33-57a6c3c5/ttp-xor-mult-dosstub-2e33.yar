rule TTP_XOR_MULT_DOSStub_2e33 {
  strings:
    $key_2e33 = { 7a 5b [2] 0e 43 [2] 49 41 [2] 0e 50 [2] 40 5c [2] 4c 56 [2] 5b 5d [2] 40 13 [2] 7d }

  condition:
    any of them
}