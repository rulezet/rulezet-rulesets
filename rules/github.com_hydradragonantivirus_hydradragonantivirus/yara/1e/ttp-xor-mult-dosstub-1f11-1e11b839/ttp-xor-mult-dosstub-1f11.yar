rule TTP_XOR_MULT_DOSStub_1f11 {
  strings:
    $key_1f11 = { 4b 79 [2] 3f 61 [2] 78 63 [2] 3f 72 [2] 71 7e [2] 7d 74 [2] 6a 7f [2] 71 31 [2] 4c }

  condition:
    any of them
}