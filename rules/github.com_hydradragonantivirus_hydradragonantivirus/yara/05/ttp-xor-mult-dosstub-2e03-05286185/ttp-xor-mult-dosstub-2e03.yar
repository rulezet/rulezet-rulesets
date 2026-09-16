rule TTP_XOR_MULT_DOSStub_2e03 {
  strings:
    $key_2e03 = { 7a 6b [2] 0e 73 [2] 49 71 [2] 0e 60 [2] 40 6c [2] 4c 66 [2] 5b 6d [2] 40 23 [2] 7d }

  condition:
    any of them
}