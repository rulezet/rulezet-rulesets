rule TTP_XOR_MULT_DOSStub_387d {
  strings:
    $key_387d = { 6c 15 [2] 18 0d [2] 5f 0f [2] 18 1e [2] 56 12 [2] 5a 18 [2] 4d 13 [2] 56 5d [2] 6b }

  condition:
    any of them
}