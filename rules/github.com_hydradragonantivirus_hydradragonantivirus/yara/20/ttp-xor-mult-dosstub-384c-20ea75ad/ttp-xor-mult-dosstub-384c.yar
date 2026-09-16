rule TTP_XOR_MULT_DOSStub_384c {
  strings:
    $key_384c = { 6c 24 [2] 18 3c [2] 5f 3e [2] 18 2f [2] 56 23 [2] 5a 29 [2] 4d 22 [2] 56 6c [2] 6b }

  condition:
    any of them
}