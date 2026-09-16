rule TTP_XOR_MULT_DOSStub_1f24 {
  strings:
    $key_1f24 = { 4b 4c [2] 3f 54 [2] 78 56 [2] 3f 47 [2] 71 4b [2] 7d 41 [2] 6a 4a [2] 71 04 [2] 4c }

  condition:
    any of them
}