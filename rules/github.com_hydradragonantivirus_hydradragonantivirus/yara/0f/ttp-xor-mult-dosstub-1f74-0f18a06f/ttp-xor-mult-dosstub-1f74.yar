rule TTP_XOR_MULT_DOSStub_1f74 {
  strings:
    $key_1f74 = { 4b 1c [2] 3f 04 [2] 78 06 [2] 3f 17 [2] 71 1b [2] 7d 11 [2] 6a 1a [2] 71 54 [2] 4c }

  condition:
    any of them
}