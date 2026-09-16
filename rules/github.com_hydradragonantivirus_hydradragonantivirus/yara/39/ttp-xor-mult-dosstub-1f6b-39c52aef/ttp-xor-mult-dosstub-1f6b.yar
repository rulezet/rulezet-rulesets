rule TTP_XOR_MULT_DOSStub_1f6b {
  strings:
    $key_1f6b = { 4b 03 [2] 3f 1b [2] 78 19 [2] 3f 08 [2] 71 04 [2] 7d 0e [2] 6a 05 [2] 71 4b [2] 4c }

  condition:
    any of them
}