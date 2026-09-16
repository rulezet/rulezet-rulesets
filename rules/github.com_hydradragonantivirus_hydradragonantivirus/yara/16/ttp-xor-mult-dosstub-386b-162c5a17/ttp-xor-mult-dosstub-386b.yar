rule TTP_XOR_MULT_DOSStub_386b {
  strings:
    $key_386b = { 6c 03 [2] 18 1b [2] 5f 19 [2] 18 08 [2] 56 04 [2] 5a 0e [2] 4d 05 [2] 56 4b [2] 6b }

  condition:
    any of them
}