rule TTP_XOR_MULT_DOSStub_1f7c {
  strings:
    $key_1f7c = { 4b 14 [2] 3f 0c [2] 78 0e [2] 3f 1f [2] 71 13 [2] 7d 19 [2] 6a 12 [2] 71 5c [2] 4c }

  condition:
    any of them
}