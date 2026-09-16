rule TTP_XOR_MULT_DOSStub_1f7d {
  strings:
    $key_1f7d = { 4b 15 [2] 3f 0d [2] 78 0f [2] 3f 1e [2] 71 12 [2] 7d 18 [2] 6a 13 [2] 71 5d [2] 4c }

  condition:
    any of them
}