rule TTP_XOR_MULT_DOSStub_477c {
  strings:
    $key_477c = { 13 14 [2] 67 0c [2] 20 0e [2] 67 1f [2] 29 13 [2] 25 19 [2] 32 12 [2] 29 5c [2] 14 }

  condition:
    any of them
}