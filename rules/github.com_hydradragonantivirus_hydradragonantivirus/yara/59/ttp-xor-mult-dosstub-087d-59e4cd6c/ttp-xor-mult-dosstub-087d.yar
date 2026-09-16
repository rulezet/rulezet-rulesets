rule TTP_XOR_MULT_DOSStub_087d {
  strings:
    $key_087d = { 5c 15 [2] 28 0d [2] 6f 0f [2] 28 1e [2] 66 12 [2] 6a 18 [2] 7d 13 [2] 66 5d [2] 5b }

  condition:
    any of them
}