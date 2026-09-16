rule TTP_XOR_MULT_DOSStub_311d {
  strings:
    $key_311d = { 65 75 [2] 11 6d [2] 56 6f [2] 11 7e [2] 5f 72 [2] 53 78 [2] 44 73 [2] 5f 3d [2] 62 }

  condition:
    any of them
}