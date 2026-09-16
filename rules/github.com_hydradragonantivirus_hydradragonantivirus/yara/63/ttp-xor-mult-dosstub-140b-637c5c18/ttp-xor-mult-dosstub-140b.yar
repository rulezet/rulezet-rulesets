rule TTP_XOR_MULT_DOSStub_140b {
  strings:
    $key_140b = { 40 63 [2] 34 7b [2] 73 79 [2] 34 68 [2] 7a 64 [2] 76 6e [2] 61 65 [2] 7a 2b [2] 47 }

  condition:
    any of them
}