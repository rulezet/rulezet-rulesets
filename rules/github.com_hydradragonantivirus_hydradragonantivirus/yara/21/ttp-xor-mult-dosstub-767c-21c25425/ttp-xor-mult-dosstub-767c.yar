rule TTP_XOR_MULT_DOSStub_767c {
  strings:
    $key_767c = { 22 14 [2] 56 0c [2] 11 0e [2] 56 1f [2] 18 13 [2] 14 19 [2] 03 12 [2] 18 5c [2] 25 }

  condition:
    any of them
}