rule TTP_XOR_MULT_DOSStub_5f7b {
  strings:
    $key_5f7b = { 0b 13 [2] 7f 0b [2] 38 09 [2] 7f 18 [2] 31 14 [2] 3d 1e [2] 2a 15 [2] 31 5b [2] 0c }

  condition:
    any of them
}