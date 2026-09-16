rule TTP_XOR_MULT_DOSStub_5f7c {
  strings:
    $key_5f7c = { 0b 14 [2] 7f 0c [2] 38 0e [2] 7f 1f [2] 31 13 [2] 3d 19 [2] 2a 12 [2] 31 5c [2] 0c }

  condition:
    any of them
}