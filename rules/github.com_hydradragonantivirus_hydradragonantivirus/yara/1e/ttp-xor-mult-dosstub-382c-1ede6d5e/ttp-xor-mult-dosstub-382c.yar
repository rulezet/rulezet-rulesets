rule TTP_XOR_MULT_DOSStub_382c {
  strings:
    $key_382c = { 6c 44 [2] 18 5c [2] 5f 5e [2] 18 4f [2] 56 43 [2] 5a 49 [2] 4d 42 [2] 56 0c [2] 6b }

  condition:
    any of them
}