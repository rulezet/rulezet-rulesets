rule TTP_XOR_MULT_DOSStub_111b {
  strings:
    $key_111b = { 45 73 [2] 31 6b [2] 76 69 [2] 31 78 [2] 7f 74 [2] 73 7e [2] 64 75 [2] 7f 3b [2] 42 }

  condition:
    any of them
}