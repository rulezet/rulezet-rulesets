rule TTP_XOR_MULT_DOSStub_1f26 {
  strings:
    $key_1f26 = { 4b 4e [2] 3f 56 [2] 78 54 [2] 3f 45 [2] 71 49 [2] 7d 43 [2] 6a 48 [2] 71 06 [2] 4c }

  condition:
    any of them
}