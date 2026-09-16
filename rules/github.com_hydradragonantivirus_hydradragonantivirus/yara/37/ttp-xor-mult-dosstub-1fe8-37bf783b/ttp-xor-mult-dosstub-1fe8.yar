rule TTP_XOR_MULT_DOSStub_1fe8 {
  strings:
    $key_1fe8 = { 4b 80 [2] 3f 98 [2] 78 9a [2] 3f 8b [2] 71 87 [2] 7d 8d [2] 6a 86 [2] 71 c8 [2] 4c }

  condition:
    any of them
}