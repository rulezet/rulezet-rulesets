rule TTP_XOR_MULT_DOSStub_1fe7 {
  strings:
    $key_1fe7 = { 4b 8f [2] 3f 97 [2] 78 95 [2] 3f 84 [2] 71 88 [2] 7d 82 [2] 6a 89 [2] 71 c7 [2] 4c }

  condition:
    any of them
}