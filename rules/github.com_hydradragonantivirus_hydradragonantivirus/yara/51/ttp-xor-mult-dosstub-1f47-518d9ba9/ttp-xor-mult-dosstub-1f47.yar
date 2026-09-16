rule TTP_XOR_MULT_DOSStub_1f47 {
  strings:
    $key_1f47 = { 4b 2f [2] 3f 37 [2] 78 35 [2] 3f 24 [2] 71 28 [2] 7d 22 [2] 6a 29 [2] 71 67 [2] 4c }

  condition:
    any of them
}