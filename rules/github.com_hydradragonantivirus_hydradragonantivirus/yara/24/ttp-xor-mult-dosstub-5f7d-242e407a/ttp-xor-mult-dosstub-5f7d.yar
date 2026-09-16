rule TTP_XOR_MULT_DOSStub_5f7d {
  strings:
    $key_5f7d = { 0b 15 [2] 7f 0d [2] 38 0f [2] 7f 1e [2] 31 12 [2] 3d 18 [2] 2a 13 [2] 31 5d [2] 0c }

  condition:
    any of them
}