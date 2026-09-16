rule TTP_XOR_MULT_DOSStub_161b {
  strings:
    $key_161b = { 42 73 [2] 36 6b [2] 71 69 [2] 36 78 [2] 78 74 [2] 74 7e [2] 63 75 [2] 78 3b [2] 45 }

  condition:
    any of them
}