rule TTP_XOR_MULT_DOSStub_231b {
  strings:
    $key_231b = { 77 73 [2] 03 6b [2] 44 69 [2] 03 78 [2] 4d 74 [2] 41 7e [2] 56 75 [2] 4d 3b [2] 70 }

  condition:
    any of them
}