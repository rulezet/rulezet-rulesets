rule TTP_XOR_MULT_DOSStub_2e55 {
  strings:
    $key_2e55 = { 7a 3d [2] 0e 25 [2] 49 27 [2] 0e 36 [2] 40 3a [2] 4c 30 [2] 5b 3b [2] 40 75 [2] 7d }

  condition:
    any of them
}