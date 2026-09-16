rule TTP_XOR_MULT_DOSStub_631b {
  strings:
    $key_631b = { 37 73 [2] 43 6b [2] 04 69 [2] 43 78 [2] 0d 74 [2] 01 7e [2] 16 75 [2] 0d 3b [2] 30 }

  condition:
    any of them
}