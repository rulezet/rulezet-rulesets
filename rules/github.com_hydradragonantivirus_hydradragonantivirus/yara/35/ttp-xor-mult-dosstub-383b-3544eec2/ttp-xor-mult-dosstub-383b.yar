rule TTP_XOR_MULT_DOSStub_383b {
  strings:
    $key_383b = { 6c 53 [2] 18 4b [2] 5f 49 [2] 18 58 [2] 56 54 [2] 5a 5e [2] 4d 55 [2] 56 1b [2] 6b }

  condition:
    any of them
}