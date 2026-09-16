rule TTP_XOR_MULT_DOSStub_1f71 {
  strings:
    $key_1f71 = { 4b 19 [2] 3f 01 [2] 78 03 [2] 3f 12 [2] 71 1e [2] 7d 14 [2] 6a 1f [2] 71 51 [2] 4c }

  condition:
    any of them
}