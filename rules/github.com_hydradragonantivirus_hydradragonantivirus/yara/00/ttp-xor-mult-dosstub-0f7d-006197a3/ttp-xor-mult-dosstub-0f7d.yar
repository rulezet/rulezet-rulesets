rule TTP_XOR_MULT_DOSStub_0f7d {
  strings:
    $key_0f7d = { 5b 15 [2] 2f 0d [2] 68 0f [2] 2f 1e [2] 61 12 [2] 6d 18 [2] 7a 13 [2] 61 5d [2] 5c }

  condition:
    any of them
}