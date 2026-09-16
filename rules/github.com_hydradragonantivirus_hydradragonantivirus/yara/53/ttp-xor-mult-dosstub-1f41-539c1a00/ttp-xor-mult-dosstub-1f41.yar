rule TTP_XOR_MULT_DOSStub_1f41 {
  strings:
    $key_1f41 = { 4b 29 [2] 3f 31 [2] 78 33 [2] 3f 22 [2] 71 2e [2] 7d 24 [2] 6a 2f [2] 71 61 [2] 4c }

  condition:
    any of them
}