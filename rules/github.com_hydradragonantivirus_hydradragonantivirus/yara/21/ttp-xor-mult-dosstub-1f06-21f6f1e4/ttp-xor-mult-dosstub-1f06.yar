rule TTP_XOR_MULT_DOSStub_1f06 {
  strings:
    $key_1f06 = { 4b 6e [2] 3f 76 [2] 78 74 [2] 3f 65 [2] 71 69 [2] 7d 63 [2] 6a 68 [2] 71 26 [2] 4c }

  condition:
    any of them
}