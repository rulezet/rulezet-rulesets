rule TTP_XOR_MULT_DOSStub_477d {
  strings:
    $key_477d = { 13 15 [2] 67 0d [2] 20 0f [2] 67 1e [2] 29 12 [2] 25 18 [2] 32 13 [2] 29 5d [2] 14 }

  condition:
    any of them
}