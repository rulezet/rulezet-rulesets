rule TTP_XOR_MULT_DOSStub_1f2b {
  strings:
    $key_1f2b = { 4b 43 [2] 3f 5b [2] 78 59 [2] 3f 48 [2] 71 44 [2] 7d 4e [2] 6a 45 [2] 71 0b [2] 4c }

  condition:
    any of them
}